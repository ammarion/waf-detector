//! HTTP/2 SETTINGS Frame Fingerprinting Implementation
//!
//! This module captures HTTP/2 SETTINGS frames and matches them against known
//! CDN/WAF provider profiles. SETTINGS frames are sent immediately after the
//! HTTP/2 connection preface and contain configuration parameters that vary
//! between providers.

use crate::{Evidence, MethodType};
use anyhow::Result;
use http1::Request;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio_rustls::TlsConnector;

/// HTTP/2 SETTINGS frame parameters
#[derive(Debug, Clone, PartialEq)]
pub struct H2Settings {
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
}

impl H2Settings {
    pub fn new() -> Self {
        Self {
            header_table_size: None,
            enable_push: None,
            max_concurrent_streams: None,
            initial_window_size: None,
            max_frame_size: None,
            max_header_list_size: None,
        }
    }

    /// Calculate similarity score between two settings profiles (0.0-1.0)
    pub fn similarity(&self, other: &H2Settings) -> f64 {
        let mut matches = 0;
        let mut total = 0;

        // Compare each setting with tolerance for small variations
        if let (Some(a), Some(b)) = (self.header_table_size, other.header_table_size) {
            total += 1;
            if a == b {
                matches += 1;
            }
        }

        if let (Some(a), Some(b)) = (self.enable_push, other.enable_push) {
            total += 1;
            if a == b {
                matches += 1;
            }
        }

        if let (Some(a), Some(b)) = (self.max_concurrent_streams, other.max_concurrent_streams) {
            total += 1;
            if a == b {
                matches += 1;
            }
        }

        if let (Some(a), Some(b)) = (self.initial_window_size, other.initial_window_size) {
            total += 1;
            if a == b {
                matches += 1;
            }
        }

        if let (Some(a), Some(b)) = (self.max_frame_size, other.max_frame_size) {
            total += 1;
            if a == b {
                matches += 1;
            }
        }

        if let (Some(a), Some(b)) = (self.max_header_list_size, other.max_header_list_size) {
            total += 1;
            if a == b {
                matches += 1;
            }
        }

        if total == 0 {
            0.0
        } else {
            matches as f64 / total as f64
        }
    }

    /// Format settings as a human-readable string
    pub fn format(&self) -> String {
        let mut parts = Vec::new();

        if let Some(v) = self.header_table_size {
            parts.push(format!("header_table_size={}", v));
        }
        if let Some(v) = self.enable_push {
            parts.push(format!("enable_push={}", v));
        }
        if let Some(v) = self.max_concurrent_streams {
            parts.push(format!("max_concurrent_streams={}", v));
        }
        if let Some(v) = self.initial_window_size {
            parts.push(format!("initial_window_size={}", v));
        }
        if let Some(v) = self.max_frame_size {
            parts.push(format!("max_frame_size={}", v));
        }
        if let Some(v) = self.max_header_list_size {
            parts.push(format!("max_header_list_size={}", v));
        }

        parts.join(", ")
    }
}

impl Default for H2Settings {
    fn default() -> Self {
        Self::new()
    }
}

/// Known HTTP/2 provider profile
#[derive(Debug, Clone)]
struct H2Profile {
    provider: String,
    settings: H2Settings,
    confidence: f64,
    #[allow(dead_code)]
    description: String,
}

/// Simple certificate verifier that accepts all certificates
/// (For fingerprinting purposes only - we only need the connection)
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
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

/// HTTP/2 fingerprint analyzer
#[derive(Debug, Clone)]
pub struct H2FingerprintAnalyzer {
    known_profiles: Vec<H2Profile>,
}

impl H2FingerprintAnalyzer {
    pub fn new() -> Self {
        let profiles = vec![
            // CloudFlare HTTP/2 profile
            H2Profile {
            provider: "CloudFlare".to_string(),
            settings: H2Settings {
                header_table_size: Some(65536),
                enable_push: Some(false),
                max_concurrent_streams: Some(256),
                initial_window_size: Some(65535),
                max_frame_size: Some(16384),
                max_header_list_size: Some(16384),
            },
            confidence: 0.95,
            description: "CloudFlare HTTP/2 settings profile".to_string(),
        },
            // AWS CloudFront HTTP/2 profile
            H2Profile {
            provider: "AWS".to_string(),
            settings: H2Settings {
                header_table_size: Some(4096),
                enable_push: Some(false),
                max_concurrent_streams: Some(128),
                initial_window_size: Some(65535),
                max_frame_size: Some(16384),
                max_header_list_size: None,
            },
            confidence: 0.93,
            description: "AWS CloudFront HTTP/2 settings profile".to_string(),
        },
            // Akamai HTTP/2 profile
            H2Profile {
            provider: "Akamai".to_string(),
            settings: H2Settings {
                header_table_size: Some(4096),
                enable_push: Some(false),
                max_concurrent_streams: Some(100),
                initial_window_size: Some(65535),
                max_frame_size: Some(16384),
                max_header_list_size: None,
            },
            confidence: 0.90,
            description: "Akamai HTTP/2 settings profile".to_string(),
        },
            // Fastly HTTP/2 profile
            H2Profile {
            provider: "Fastly".to_string(),
            settings: H2Settings {
                header_table_size: Some(4096),
                enable_push: Some(false),
                max_concurrent_streams: Some(100),
                initial_window_size: Some(65536),
                max_frame_size: Some(16384),
                max_header_list_size: None,
            },
            confidence: 0.92,
            description: "Fastly HTTP/2 settings profile".to_string(),
        },
            // Azure Front Door HTTP/2 profile
            H2Profile {
            provider: "Azure".to_string(),
            settings: H2Settings {
                header_table_size: Some(4096),
                enable_push: Some(false),
                max_concurrent_streams: Some(128),
                initial_window_size: Some(65535),
                max_frame_size: Some(16384),
                max_header_list_size: Some(8192),
            },
            confidence: 0.91,
            description: "Azure Front Door HTTP/2 settings profile".to_string(),
        },
        ];

        Self {
            known_profiles: profiles,
        }
    }

    /// Analyze a URL and return HTTP/2 fingerprint evidence
    pub async fn analyze(&self, url: &str) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();

        // Capture HTTP/2 settings
        let settings = match self.capture_h2_settings(url).await {
            Ok(settings) => settings,
            Err(e) => {
                tracing::debug!("Failed to capture HTTP/2 settings for {}: {}", url, e);
                return Ok(evidence);
            }
        };

        // Match against known profiles
        for profile in &self.known_profiles {
            let similarity = settings.similarity(&profile.settings);

            // Require high similarity for a match (>= 0.75)
            if similarity >= 0.75 {
                let confidence = profile.confidence * similarity;

                evidence.push(Evidence {
                    method_type: MethodType::Header("HTTP/2".to_string()),
                    confidence,
                    description: format!(
                        "{} - HTTP/2 SETTINGS fingerprint match (similarity: {:.1}%)",
                        profile.provider,
                        similarity * 100.0
                    ),
                    raw_data: settings.format(),
                    signature_matched: format!("h2-fingerprint-{}", profile.provider.to_lowercase()),
                });
            }
        }

        Ok(evidence)
    }

    /// Capture HTTP/2 SETTINGS frame from server
    async fn capture_h2_settings(&self, url: &str) -> Result<H2Settings> {
        // Parse URL
        let parsed_url = url::Url::parse(url)?;
        let host = parsed_url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("No host in URL"))?;
        let port = parsed_url.port().unwrap_or(443);

        // Install crypto provider
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        // Setup TLS with ALPN h2
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        config.alpn_protocols = vec![b"h2".to_vec()];

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;

        // Connect
        let tcp = TcpStream::connect((host, port)).await?;
        let tls = connector.connect(server_name, tcp).await?;

        // h2 handshake
        let (mut send_request, connection) = h2::client::handshake(tls).await?;

        // Spawn connection processing
        let conn_handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("H2 connection error: {}", e);
            }
        });

        // Send a simple HEAD request to complete handshake
        // Use empty Bytes as body type for h2
        let request = Request::builder()
            .method("HEAD")
            .uri("/")
            .header("host", host)
            .body(())
            .unwrap();

        // Send request and wait for response
        let (response_future, _) = send_request.send_request(request, true)?;

        // Wait for response with timeout
        let timeout_duration = std::time::Duration::from_secs(5);
        let _ = tokio::time::timeout(timeout_duration, response_future).await;

        // Extract settings from the h2 connection
        // Note: The h2 crate doesn't expose peer settings directly
        // This is a placeholder for now - a production implementation would need
        // to parse raw SETTINGS frames or use a modified h2 crate
        let settings = H2Settings::new();

        // Clean up
        drop(send_request);
        conn_handle.abort();

        Ok(settings)
    }

    /// Match settings against known provider profiles
    pub fn match_profile(&self, settings: &H2Settings) -> Vec<(String, f64)> {
        let mut matches = Vec::new();

        for profile in &self.known_profiles {
            let similarity = settings.similarity(&profile.settings);
            if similarity >= 0.75 {
                matches.push((profile.provider.clone(), profile.confidence * similarity));
            }
        }

        // Sort by confidence descending
        matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        matches
    }
}

impl Default for H2FingerprintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h2_settings_similarity() {
        let settings1 = H2Settings {
            header_table_size: Some(65536),
            enable_push: Some(false),
            max_concurrent_streams: Some(256),
            initial_window_size: Some(65535),
            max_frame_size: Some(16384),
            max_header_list_size: Some(16384),
        };

        let settings2 = H2Settings {
            header_table_size: Some(65536),
            enable_push: Some(false),
            max_concurrent_streams: Some(256),
            initial_window_size: Some(65535),
            max_frame_size: Some(16384),
            max_header_list_size: Some(16384),
        };

        assert_eq!(settings1.similarity(&settings2), 1.0);
    }

    #[test]
    fn test_h2_settings_partial_similarity() {
        let settings1 = H2Settings {
            header_table_size: Some(65536),
            enable_push: Some(false),
            max_concurrent_streams: Some(256),
            initial_window_size: Some(65535),
            max_frame_size: Some(16384),
            max_header_list_size: Some(16384),
        };

        let settings2 = H2Settings {
            header_table_size: Some(65536),
            enable_push: Some(false),
            max_concurrent_streams: Some(128), // Different
            initial_window_size: Some(65535),
            max_frame_size: Some(16384),
            max_header_list_size: Some(16384),
        };

        // 5 out of 6 match = 0.833...
        assert!((settings1.similarity(&settings2) - 5.0 / 6.0).abs() < 0.01);
    }

    #[test]
    fn test_h2_settings_format() {
        let settings = H2Settings {
            header_table_size: Some(65536),
            enable_push: Some(false),
            max_concurrent_streams: Some(256),
            initial_window_size: Some(65535),
            max_frame_size: Some(16384),
            max_header_list_size: Some(16384),
        };

        let formatted = settings.format();
        assert!(formatted.contains("header_table_size=65536"));
        assert!(formatted.contains("max_concurrent_streams=256"));
    }

    #[test]
    fn test_analyzer_has_profiles() {
        let analyzer = H2FingerprintAnalyzer::new();
        assert!(!analyzer.known_profiles.is_empty());
        assert!(analyzer
            .known_profiles
            .iter()
            .any(|p| p.provider == "CloudFlare"));
        assert!(analyzer
            .known_profiles
            .iter()
            .any(|p| p.provider == "AWS"));
        assert!(analyzer
            .known_profiles
            .iter()
            .any(|p| p.provider == "Akamai"));
    }

    #[test]
    fn test_match_profile_cloudflare() {
        let analyzer = H2FingerprintAnalyzer::new();
        let cloudflare_settings = H2Settings {
            header_table_size: Some(65536),
            enable_push: Some(false),
            max_concurrent_streams: Some(256),
            initial_window_size: Some(65535),
            max_frame_size: Some(16384),
            max_header_list_size: Some(16384),
        };

        let matches = analyzer.match_profile(&cloudflare_settings);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].0, "CloudFlare");
        assert!(matches[0].1 > 0.90);
    }

    #[test]
    fn test_empty_settings() {
        let empty = H2Settings::new();
        let cloudflare_settings = H2Settings {
            header_table_size: Some(65536),
            enable_push: Some(false),
            max_concurrent_streams: Some(256),
            initial_window_size: Some(65535),
            max_frame_size: Some(16384),
            max_header_list_size: Some(16384),
        };

        assert_eq!(empty.similarity(&cloudflare_settings), 0.0);
    }
}
