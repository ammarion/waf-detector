//! TLS/SSL Certificate Fingerprinting for WAF/CDN Detection
//!
//! This module extracts and analyzes TLS certificates to identify WAF/CDN providers.
//! Certificates are infrastructure-level and cannot be easily hidden, making them
//! highly reliable for detection.

use crate::{Evidence, MethodType};
use anyhow::Result;
use std::collections::HashMap;

/// TLS certificate analyzer
#[derive(Debug, Clone)]
pub struct TlsAnalyzer {
    provider_patterns: HashMap<String, Vec<CertificatePattern>>,
}

/// Certificate pattern for provider identification
#[derive(Debug, Clone)]
pub struct CertificatePattern {
    pub pattern_type: CertificatePatternType,
    pub pattern: String,
    pub confidence: f64,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertificatePatternType {
    Issuer,
    Subject,
    Organization,
    CommonName,
}

/// Certificate information extracted from TLS connection
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub san_entries: Vec<String>, // Subject Alternative Names
}

impl TlsAnalyzer {
    pub fn new() -> Self {
        let mut provider_patterns = HashMap::new();

        // CloudFlare certificate patterns
        provider_patterns.insert(
            "CloudFlare".to_string(),
            vec![
                CertificatePattern {
                    pattern_type: CertificatePatternType::Issuer,
                    pattern: "Cloudflare Inc".to_string(),
                    confidence: 0.98,
                    description: "CloudFlare SSL issuer".to_string(),
                },
                CertificatePattern {
                    pattern_type: CertificatePatternType::Organization,
                    pattern: "Cloudflare".to_string(),
                    confidence: 0.95,
                    description: "CloudFlare organization".to_string(),
                },
                CertificatePattern {
                    pattern_type: CertificatePatternType::CommonName,
                    pattern: "sni.cloudflaressl.com".to_string(),
                    confidence: 0.92,
                    description: "CloudFlare SNI certificate".to_string(),
                },
            ],
        );

        // Akamai certificate patterns
        provider_patterns.insert(
            "Akamai".to_string(),
            vec![
                CertificatePattern {
                    pattern_type: CertificatePatternType::Issuer,
                    pattern: "DigiCert".to_string(),
                    confidence: 0.70,
                    description: "Akamai commonly uses DigiCert".to_string(),
                },
                CertificatePattern {
                    pattern_type: CertificatePatternType::Subject,
                    pattern: "akamaized.net".to_string(),
                    confidence: 0.95,
                    description: "Akamai edge network certificate".to_string(),
                },
                CertificatePattern {
                    pattern_type: CertificatePatternType::Subject,
                    pattern: "akamaihd.net".to_string(),
                    confidence: 0.95,
                    description: "Akamai HD network certificate".to_string(),
                },
            ],
        );

        // AWS CloudFront certificate patterns
        provider_patterns.insert(
            "AWS".to_string(),
            vec![
                CertificatePattern {
                    pattern_type: CertificatePatternType::Subject,
                    pattern: "cloudfront.net".to_string(),
                    confidence: 0.98,
                    description: "AWS CloudFront certificate".to_string(),
                },
                CertificatePattern {
                    pattern_type: CertificatePatternType::Issuer,
                    pattern: "Amazon".to_string(),
                    confidence: 0.85,
                    description: "Amazon certificate authority".to_string(),
                },
            ],
        );

        // Fastly certificate patterns
        provider_patterns.insert(
            "Fastly".to_string(),
            vec![
                CertificatePattern {
                    pattern_type: CertificatePatternType::Issuer,
                    pattern: "GlobalSign".to_string(),
                    confidence: 0.75,
                    description: "Fastly uses GlobalSign".to_string(),
                },
                CertificatePattern {
                    pattern_type: CertificatePatternType::Subject,
                    pattern: "fastly.net".to_string(),
                    confidence: 0.95,
                    description: "Fastly CDN certificate".to_string(),
                },
            ],
        );

        // Azure certificate patterns
        provider_patterns.insert(
            "Azure".to_string(),
            vec![
                CertificatePattern {
                    pattern_type: CertificatePatternType::Subject,
                    pattern: "azurefd.net".to_string(),
                    confidence: 0.98,
                    description: "Azure Front Door certificate".to_string(),
                },
                CertificatePattern {
                    pattern_type: CertificatePatternType::Subject,
                    pattern: "azureedge.net".to_string(),
                    confidence: 0.98,
                    description: "Azure CDN certificate".to_string(),
                },
                CertificatePattern {
                    pattern_type: CertificatePatternType::Issuer,
                    pattern: "Microsoft".to_string(),
                    confidence: 0.80,
                    description: "Microsoft certificate authority".to_string(),
                },
            ],
        );

        // Vercel certificate patterns
        provider_patterns.insert(
            "Vercel".to_string(),
            vec![
                CertificatePattern {
                    pattern_type: CertificatePatternType::Subject,
                    pattern: "vercel.app".to_string(),
                    confidence: 0.98,
                    description: "Vercel deployment certificate".to_string(),
                },
                CertificatePattern {
                    pattern_type: CertificatePatternType::Issuer,
                    pattern: "Let's Encrypt".to_string(),
                    confidence: 0.65,
                    description: "Vercel uses Let's Encrypt".to_string(),
                },
            ],
        );

        Self { provider_patterns }
    }

    /// Analyze TLS certificate for provider identification
    pub async fn analyze(&self, url: &str) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();

        // Extract certificate info
        let cert_info = match self.extract_certificate_info(url).await {
            Ok(info) => info,
            Err(e) => {
                // Certificate extraction failed - not an error, just no TLS evidence
                tracing::debug!("TLS certificate extraction failed for {}: {}", url, e);
                return Ok(evidence);
            }
        };

        // Match against provider patterns
        for (provider_name, patterns) in &self.provider_patterns {
            for pattern in patterns {
                if self.matches_pattern(&cert_info, pattern) {
                    evidence.push(Evidence {
                        method_type: MethodType::Certificate,
                        confidence: pattern.confidence,
                        description: format!(
                            "{} - Certificate {} matches {}",
                            provider_name,
                            pattern.pattern_type.as_str(),
                            pattern.pattern
                        ),
                        raw_data: format!(
                            "Issuer: {:?}, Subject: {:?}, CN: {:?}, Org: {:?}",
                            cert_info.issuer,
                            cert_info.subject,
                            cert_info.common_name,
                            cert_info.organization
                        ),
                        signature_matched: format!(
                            "tls-{}-{}",
                            provider_name.to_lowercase(),
                            pattern.pattern_type.as_str()
                        ),
                    });
                }
            }
        }

        Ok(evidence)
    }

    /// Extract certificate information from URL
    async fn extract_certificate_info(&self, url: &str) -> Result<CertificateInfo> {
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio_rustls::rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::rustls::{
            ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
        };
        use tokio_rustls::TlsConnector;

        // Install the default crypto provider if not already installed
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        // Parse URL to get host and port
        let parsed_url = url::Url::parse(url)?;
        let host = parsed_url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("No host in URL"))?;
        let port = parsed_url.port().unwrap_or(443);

        // Create a custom verifier that captures certificates but doesn't validate
        #[derive(Debug)]
        struct CertificateCapture {
            captured_certs: Arc<std::sync::Mutex<Option<Vec<Vec<u8>>>>>,
        }

        impl ServerCertVerifier for CertificateCapture {
            fn verify_server_cert(
                &self,
                end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
                intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
                _server_name: &ServerName,
                _ocsp_response: &[u8],
                _now: tokio_rustls::rustls::pki_types::UnixTime,
            ) -> Result<ServerCertVerified, TlsError> {
                // Capture the certificates
                let mut certs = vec![end_entity.to_vec()];
                certs.extend(intermediates.iter().map(|c| c.to_vec()));
                let mut guard = self.captured_certs.lock().unwrap_or_else(|e| e.into_inner());
                *guard = Some(certs);
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, TlsError> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, TlsError> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::ED25519,
                ]
            }
        }

        let captured_certs = Arc::new(std::sync::Mutex::new(None));
        let verifier = Arc::new(CertificateCapture {
            captured_certs: Arc::clone(&captured_certs),
        });

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;

        // Connect and extract certificate
        let stream = TcpStream::connect((host, port)).await?;
        let _tls_stream = connector.connect(server_name, stream).await?;

        // Get captured certificates
        let guard = captured_certs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(certs) = guard.as_ref() {
            if let Some(cert) = certs.first() {
                return self.parse_certificate(cert);
            }
        }

        Err(anyhow::anyhow!("No certificate found"))
    }

    /// Parse certificate bytes into CertificateInfo
    fn parse_certificate(&self, cert_der: &[u8]) -> Result<CertificateInfo> {
        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(cert_der)?;

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();

        // Extract common name
        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(String::from);

        // Extract organization
        let organization = cert
            .subject()
            .iter_organization()
            .next()
            .and_then(|org| org.as_str().ok())
            .map(String::from);

        // Extract Subject Alternative Names
        let san_entries = if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            san_ext
                .value
                .general_names
                .iter()
                .filter_map(|gn| {
                    if let x509_parser::extensions::GeneralName::DNSName(name) = gn {
                        Some(name.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        Ok(CertificateInfo {
            subject: Some(subject),
            issuer: Some(issuer),
            common_name,
            organization,
            san_entries,
        })
    }

    /// Check if certificate matches a pattern
    fn matches_pattern(&self, cert_info: &CertificateInfo, pattern: &CertificatePattern) -> bool {
        let text_to_check = match pattern.pattern_type {
            CertificatePatternType::Issuer => cert_info.issuer.as_deref(),
            CertificatePatternType::Subject => cert_info.subject.as_deref(),
            CertificatePatternType::Organization => cert_info.organization.as_deref(),
            CertificatePatternType::CommonName => cert_info.common_name.as_deref(),
        };

        if let Some(text) = text_to_check {
            text.to_lowercase()
                .contains(&pattern.pattern.to_lowercase())
        } else {
            false
        }
    }
}

impl CertificatePatternType {
    fn as_str(&self) -> &str {
        match self {
            Self::Issuer => "issuer",
            Self::Subject => "subject",
            Self::Organization => "organization",
            Self::CommonName => "common_name",
        }
    }
}

impl Default for TlsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_analyzer_creation() {
        let analyzer = TlsAnalyzer::new();
        assert!(analyzer.provider_patterns.contains_key("CloudFlare"));
        assert!(analyzer.provider_patterns.contains_key("Akamai"));
        assert!(analyzer.provider_patterns.contains_key("AWS"));
    }

    #[test]
    fn test_pattern_matching() {
        let analyzer = TlsAnalyzer::new();
        let cert_info = CertificateInfo {
            subject: Some("CN=example.cloudflaressl.com".to_string()),
            issuer: Some("CN=Cloudflare Inc".to_string()),
            common_name: Some("sni.cloudflaressl.com".to_string()),
            organization: Some("Cloudflare".to_string()),
            san_entries: vec![],
        };

        let pattern = CertificatePattern {
            pattern_type: CertificatePatternType::Issuer,
            pattern: "Cloudflare".to_string(),
            confidence: 0.95,
            description: "Test".to_string(),
        };

        assert!(analyzer.matches_pattern(&cert_info, &pattern));
    }
}
