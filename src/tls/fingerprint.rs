//! TLS Fingerprinting for WAF/CDN Detection
//!
//! This module provides JA3S-inspired TLS fingerprinting by capturing negotiated
//! connection parameters (TLS version, cipher suite, ALPN) from the ServerHello.
//! While not a full JA3S implementation (which requires raw extension parsing),
//! the combination of these parameters is highly distinctive for CDN/WAF identification.

use crate::{Evidence, MethodType};
use std::collections::HashMap;

/// TLS connection metadata captured from ServerHello
#[derive(Debug, Clone)]
pub struct TlsConnectionInfo {
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn_protocol: Option<String>,
}

impl TlsConnectionInfo {
    /// Create a fingerprint string from connection info
    pub fn fingerprint_string(&self) -> String {
        format!(
            "{}|{}|{}",
            self.tls_version.as_deref().unwrap_or("unknown"),
            self.cipher_suite.as_deref().unwrap_or("unknown"),
            self.alpn_protocol.as_deref().unwrap_or("none")
        )
    }

    /// Create a compact hash of the fingerprint
    pub fn fingerprint_hash(&self) -> String {
        let fp = self.fingerprint_string();
        format!("{:x}", md5::compute(fp.as_bytes()))
    }
}

/// Database of known TLS fingerprints for CDN/WAF providers
#[derive(Debug, Clone)]
pub struct FingerprintDatabase {
    fingerprints: HashMap<String, Vec<FingerprintEntry>>,
}

#[derive(Debug, Clone)]
pub struct FingerprintEntry {
    pub provider: String,
    pub confidence: f64,
    pub description: String,
    pub tls_version: String,
    pub cipher_suite: String,
}

impl FingerprintDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            fingerprints: HashMap::new(),
        };

        // CloudFlare fingerprints
        // CloudFlare heavily uses TLS 1.3 with modern ciphers
        db.add_fingerprint(FingerprintEntry {
            provider: "CloudFlare".to_string(),
            confidence: 0.92,
            description: "CloudFlare TLS 1.3 with AES-128-GCM".to_string(),
            tls_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".to_string(),
        });

        db.add_fingerprint(FingerprintEntry {
            provider: "CloudFlare".to_string(),
            confidence: 0.92,
            description: "CloudFlare TLS 1.3 with ChaCha20".to_string(),
            tls_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_CHACHA20_POLY1305_SHA256".to_string(),
        });

        db.add_fingerprint(FingerprintEntry {
            provider: "CloudFlare".to_string(),
            confidence: 0.88,
            description: "CloudFlare TLS 1.3 with AES-256-GCM".to_string(),
            tls_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_256_GCM_SHA384".to_string(),
        });

        // AWS CloudFront fingerprints
        // CloudFront commonly uses TLS 1.2 with ECDHE-RSA
        db.add_fingerprint(FingerprintEntry {
            provider: "AWS".to_string(),
            confidence: 0.85,
            description: "AWS CloudFront TLS 1.2 ECDHE-RSA-AES128".to_string(),
            tls_version: "TLSv1_2".to_string(),
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        });

        db.add_fingerprint(FingerprintEntry {
            provider: "AWS".to_string(),
            confidence: 0.85,
            description: "AWS CloudFront TLS 1.2 ECDHE-RSA-AES256".to_string(),
            tls_version: "TLSv1_2".to_string(),
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        });

        // Akamai fingerprints
        // Akamai supports both TLS 1.2 and 1.3, various ciphers
        db.add_fingerprint(FingerprintEntry {
            provider: "Akamai".to_string(),
            confidence: 0.80,
            description: "Akamai TLS 1.2 ECDHE-RSA-AES128".to_string(),
            tls_version: "TLSv1_2".to_string(),
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        });

        db.add_fingerprint(FingerprintEntry {
            provider: "Akamai".to_string(),
            confidence: 0.82,
            description: "Akamai TLS 1.3 with AES-256-GCM".to_string(),
            tls_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_256_GCM_SHA384".to_string(),
        });

        // Fastly fingerprints
        // Fastly uses TLS 1.3 with modern ciphers
        db.add_fingerprint(FingerprintEntry {
            provider: "Fastly".to_string(),
            confidence: 0.88,
            description: "Fastly TLS 1.3 with AES-256-GCM".to_string(),
            tls_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_256_GCM_SHA384".to_string(),
        });

        db.add_fingerprint(FingerprintEntry {
            provider: "Fastly".to_string(),
            confidence: 0.88,
            description: "Fastly TLS 1.3 with AES-128-GCM".to_string(),
            tls_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".to_string(),
        });

        // Azure Front Door fingerprints
        db.add_fingerprint(FingerprintEntry {
            provider: "Azure".to_string(),
            confidence: 0.83,
            description: "Azure Front Door TLS 1.2 ECDHE-RSA".to_string(),
            tls_version: "TLSv1_2".to_string(),
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        });

        db.add_fingerprint(FingerprintEntry {
            provider: "Azure".to_string(),
            confidence: 0.85,
            description: "Azure Front Door TLS 1.3".to_string(),
            tls_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_256_GCM_SHA384".to_string(),
        });

        // Imperva/Incapsula fingerprints
        db.add_fingerprint(FingerprintEntry {
            provider: "Imperva".to_string(),
            confidence: 0.86,
            description: "Imperva TLS 1.2 ECDHE-RSA-AES256".to_string(),
            tls_version: "TLSv1_2".to_string(),
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384".to_string(),
        });

        db.add_fingerprint(FingerprintEntry {
            provider: "Imperva".to_string(),
            confidence: 0.84,
            description: "Imperva TLS 1.2 ECDHE-RSA-AES128".to_string(),
            tls_version: "TLSv1_2".to_string(),
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256".to_string(),
        });

        db
    }

    fn add_fingerprint(&mut self, entry: FingerprintEntry) {
        let key = Self::make_key(&entry.tls_version, &entry.cipher_suite);
        self.fingerprints.entry(key).or_default().push(entry);
    }

    fn make_key(tls_version: &str, cipher_suite: &str) -> String {
        format!("{}:{}", tls_version, cipher_suite)
    }

    /// Lookup fingerprint matches for given connection info
    pub fn lookup(&self, conn_info: &TlsConnectionInfo) -> Vec<&FingerprintEntry> {
        let mut matches = Vec::new();

        if let (Some(tls_ver), Some(cipher)) = (&conn_info.tls_version, &conn_info.cipher_suite) {
            let key = Self::make_key(tls_ver, cipher);
            if let Some(entries) = self.fingerprints.get(&key) {
                matches.extend(entries.iter());
            }
        }

        matches
    }

    /// Generate Evidence items from TLS connection info
    pub fn analyze(&self, conn_info: &TlsConnectionInfo) -> Vec<Evidence> {
        let mut evidence = Vec::new();
        let matches = self.lookup(conn_info);

        for entry in matches {
            evidence.push(Evidence {
                method_type: MethodType::Certificate, // Using Certificate type for TLS-level detection
                confidence: entry.confidence,
                description: format!("{} - {}", entry.provider, entry.description),
                raw_data: format!(
                    "TLS Fingerprint: {} | Cipher: {} | ALPN: {} | Hash: {}",
                    conn_info.tls_version.as_deref().unwrap_or("unknown"),
                    conn_info.cipher_suite.as_deref().unwrap_or("unknown"),
                    conn_info.alpn_protocol.as_deref().unwrap_or("none"),
                    conn_info.fingerprint_hash()
                ),
                signature_matched: format!("tls-fingerprint-{}", entry.provider.to_lowercase()),
            });
        }

        evidence
    }
}

impl Default for FingerprintDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_string() {
        let conn_info = TlsConnectionInfo {
            tls_version: Some("TLSv1_3".to_string()),
            cipher_suite: Some("TLS13_AES_128_GCM_SHA256".to_string()),
            alpn_protocol: Some("h2".to_string()),
        };

        let fp = conn_info.fingerprint_string();
        assert_eq!(fp, "TLSv1_3|TLS13_AES_128_GCM_SHA256|h2");
    }

    #[test]
    fn test_fingerprint_hash() {
        let conn_info = TlsConnectionInfo {
            tls_version: Some("TLSv1_3".to_string()),
            cipher_suite: Some("TLS13_AES_128_GCM_SHA256".to_string()),
            alpn_protocol: Some("h2".to_string()),
        };

        let hash = conn_info.fingerprint_hash();
        // MD5 hash should be 32 hex characters
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_database_lookup() {
        let db = FingerprintDatabase::new();

        // Test CloudFlare lookup
        let cloudflare_conn = TlsConnectionInfo {
            tls_version: Some("TLSv1_3".to_string()),
            cipher_suite: Some("TLS13_AES_128_GCM_SHA256".to_string()),
            alpn_protocol: Some("h2".to_string()),
        };

        let matches = db.lookup(&cloudflare_conn);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].provider, "CloudFlare");
    }

    #[test]
    fn test_analyze_generates_evidence() {
        let db = FingerprintDatabase::new();

        let conn_info = TlsConnectionInfo {
            tls_version: Some("TLSv1_3".to_string()),
            cipher_suite: Some("TLS13_AES_128_GCM_SHA256".to_string()),
            alpn_protocol: Some("h2".to_string()),
        };

        let evidence = db.analyze(&conn_info);
        assert!(!evidence.is_empty());
        assert!(evidence[0]
            .signature_matched
            .starts_with("tls-fingerprint-"));
    }

    #[test]
    fn test_unknown_fingerprint() {
        let db = FingerprintDatabase::new();

        let unknown_conn = TlsConnectionInfo {
            tls_version: Some("TLSv1_0".to_string()),
            cipher_suite: Some("UNKNOWN_CIPHER".to_string()),
            alpn_protocol: None,
        };

        let evidence = db.analyze(&unknown_conn);
        assert!(evidence.is_empty());
    }
}
