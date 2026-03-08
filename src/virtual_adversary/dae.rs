use crate::payload::waf_smoke_test::WafSmokeTest;
use anyhow::{anyhow, Result};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeClass {
    ParserAmbiguity,
    ProtocolMutation,
    EncodingBoundary,
    BehavioralThrottle,
    ResponseFingerprint,
    SemanticDrift,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeChannel {
    Path,
    Query,
    Header,
    Body,
    Method,
    Cookie,
}

#[derive(Debug, Clone)]
pub struct Probe {
    pub class: ProbeClass,
    pub channel: ProbeChannel,
    pub description: &'static str,
    pub payload: String,
    pub headers: Vec<(String, String)>,
    pub method: &'static str,
    pub body: Option<String>,
}

#[allow(clippy::vec_init_then_push)]
pub fn probe_catalog_for_tier(tier: u8) -> Result<Vec<Probe>> {
    if !(1..=3).contains(&tier) {
        return Err(anyhow!("tier must be between 1 and 3"));
    }
    let mut probes = Vec::new();

    // Tier 1: protocol-safe, low-risk probes
    probes.push(Probe {
        class: ProbeClass::SemanticDrift,
        channel: ProbeChannel::Path,
        description: "Path normalization drift",
        payload: "/.%2e/%2e%2e/".to_string(),
        headers: Vec::new(),
        method: "GET",
        body: None,
    });
    probes.push(Probe {
        class: ProbeClass::SemanticDrift,
        channel: ProbeChannel::Query,
        description: "Duplicate key ordering drift",
        payload: "a=1&a=2&b=1".to_string(),
        headers: Vec::new(),
        method: "GET",
        body: None,
    });
    probes.push(Probe {
        class: ProbeClass::ProtocolMutation,
        channel: ProbeChannel::Header,
        description: "Case and whitespace header mutation",
        payload: "x-forwarded-host".to_string(),
        headers: vec![
            (
                "X-FORWARDED-HOST".to_string(),
                "example.invalid".to_string(),
            ),
            (
                "x-forwarded-host".to_string(),
                "example.invalid".to_string(),
            ),
            (
                "X-FORWARDED-HOST".to_string(),
                "example.invalid".to_string(),
            ),
            (
                "x-forwarded-host".to_string(),
                "example.invalid".to_string(),
            ),
        ],
        method: "GET",
        body: None,
    });
    probes.push(Probe {
        class: ProbeClass::ProtocolMutation,
        channel: ProbeChannel::Header,
        description: "Mixed-case hop header probe",
        payload: "connection-keep-alive".to_string(),
        headers: vec![
            ("CoNnEcTiOn".to_string(), "keep-alive".to_string()),
            ("Keep-Alive".to_string(), "timeout=5".to_string()),
        ],
        method: "GET",
        body: None,
    });
    probes.push(Probe {
        class: ProbeClass::EncodingBoundary,
        channel: ProbeChannel::Query,
        description: "Double-encoding boundary probe",
        payload: "q=%252e%252e%252f".to_string(),
        headers: Vec::new(),
        method: "GET",
        body: None,
    });
    probes.push(Probe {
        class: ProbeClass::EncodingBoundary,
        channel: ProbeChannel::Cookie,
        description: "Cookie encoding boundary probe",
        payload: "sess=%2575%2573%2572".to_string(),
        headers: Vec::new(),
        method: "GET",
        body: None,
    });
    probes.push(Probe {
        class: ProbeClass::ResponseFingerprint,
        channel: ProbeChannel::Header,
        description: "Content negotiation fingerprint",
        payload: "accept=application/xml".to_string(),
        headers: vec![("Accept".to_string(), "application/xml".to_string())],
        method: "GET",
        body: None,
    });
    probes.push(Probe {
        class: ProbeClass::ResponseFingerprint,
        channel: ProbeChannel::Header,
        description: "Language fingerprint",
        payload: "accept-language=tr-TR".to_string(),
        headers: vec![("Accept-Language".to_string(), "tr-TR,tr;q=0.9".to_string())],
        method: "GET",
        body: None,
    });
    // A-1: XFF loopback spoof
    probes.push(Probe {
        class: ProbeClass::ProtocolMutation,
        channel: ProbeChannel::Header,
        description: "XFF loopback spoof",
        payload: "xff-loopback-spoof".to_string(),
        headers: vec![("X-Forwarded-For".to_string(), "127.0.0.1".to_string())],
        method: "GET",
        body: None,
    });
    // A-9: HTTP/1.0 downgrade signal
    probes.push(Probe {
        class: ProbeClass::ProtocolMutation,
        channel: ProbeChannel::Header,
        description: "HTTP/1.0 downgrade via proxy hint",
        payload: "http10-downgrade-via".to_string(),
        headers: vec![
            ("Via".to_string(), "1.0 proxy.legacy.internal".to_string()),
            ("Pragma".to_string(), "no-cache".to_string()),
        ],
        method: "GET",
        body: None,
    });
    // A-10: Method override
    probes.push(Probe {
        class: ProbeClass::SemanticDrift,
        channel: ProbeChannel::Header,
        description: "HTTP method override via header",
        payload: "method-override-delete".to_string(),
        headers: vec![
            ("X-HTTP-Method-Override".to_string(), "DELETE".to_string()),
            ("X-Method-Override".to_string(), "DELETE".to_string()),
        ],
        method: "GET",
        body: None,
    });
    // A-11: Tab in path
    probes.push(Probe {
        class: ProbeClass::EncodingBoundary,
        channel: ProbeChannel::Path,
        description: "Tab character in path (CVE-2024-1019)",
        payload: "/admin%09".to_string(),
        headers: Vec::new(),
        method: "GET",
        body: None,
    });
    // A-12: %3f path confusion
    probes.push(Probe {
        class: ProbeClass::SemanticDrift,
        channel: ProbeChannel::Path,
        description: "Percent-encoded question mark path confusion",
        payload: "/%3fadmin-path-confusion".to_string(),
        headers: Vec::new(),
        method: "GET",
        body: None,
    });
    // A-13: Geolocation header spoof
    probes.push(Probe {
        class: ProbeClass::ProtocolMutation,
        channel: ProbeChannel::Header,
        description: "Geolocation header spoof",
        payload: "geo-header-spoof".to_string(),
        headers: vec![
            ("CF-IPCountry".to_string(), "US".to_string()),
            ("CloudFront-Viewer-Country".to_string(), "US".to_string()),
            ("X-Country-Code".to_string(), "US".to_string()),
        ],
        method: "GET",
        body: None,
    });

    if tier >= 2 {
        probes.push(Probe {
            class: ProbeClass::ParserAmbiguity,
            channel: ProbeChannel::Header,
            description: "Duplicate header ambiguity",
            payload: "content-length-conflict".to_string(),
            headers: vec![
                ("Content-Length".to_string(), "4".to_string()),
                ("Content-Length".to_string(), "10".to_string()),
            ],
            method: "POST",
            body: Some("test".to_string()),
        });
        probes.push(Probe {
            class: ProbeClass::SemanticDrift,
            channel: ProbeChannel::Query,
            description: "Duplicate query key drift",
            payload: "id=1&id=2".to_string(),
            headers: Vec::new(),
            method: "GET",
            body: None,
        });
        probes.push(Probe {
            class: ProbeClass::ParserAmbiguity,
            channel: ProbeChannel::Header,
            description: "Whitespace header fold probe",
            payload: "folded-header".to_string(),
            headers: vec![("X-WAF-Note".to_string(), "line1\r\n line2".to_string())],
            method: "GET",
            body: None,
        });
        probes.push(Probe {
            class: ProbeClass::EncodingBoundary,
            channel: ProbeChannel::Query,
            description: "Unicode normalization boundary",
            payload: "q=%E2%85%A0".to_string(), // Roman numeral one
            headers: Vec::new(),
            method: "GET",
            body: None,
        });
        // A-2: IP trust header cluster
        probes.push(Probe {
            class: ProbeClass::ProtocolMutation,
            channel: ProbeChannel::Header,
            description: "IP trust header cluster",
            payload: "ip-trust-header-cluster".to_string(),
            headers: vec![
                ("X-Real-IP".to_string(), "127.0.0.1".to_string()),
                ("True-Client-IP".to_string(), "127.0.0.1".to_string()),
                ("CF-Connecting-IP".to_string(), "127.0.0.1".to_string()),
            ],
            method: "GET",
            body: None,
        });
        // A-3: X-Original-URL override
        probes.push(Probe {
            class: ProbeClass::SemanticDrift,
            channel: ProbeChannel::Header,
            description: "X-Original-URL path override",
            payload: "x-original-url-override".to_string(),
            headers: vec![("X-Original-URL".to_string(), "/admin".to_string())],
            method: "GET",
            body: None,
        });
        // A-4: X-Rewrite-URL override
        probes.push(Probe {
            class: ProbeClass::SemanticDrift,
            channel: ProbeChannel::Header,
            description: "X-Rewrite-URL path override",
            payload: "x-rewrite-url-override".to_string(),
            headers: vec![("X-Rewrite-URL".to_string(), "/admin".to_string())],
            method: "GET",
            body: None,
        });
        // A-5: h2c cleartext upgrade
        probes.push(Probe {
            class: ProbeClass::ProtocolMutation,
            channel: ProbeChannel::Header,
            description: "h2c cleartext upgrade probe",
            payload: "h2c-upgrade-probe".to_string(),
            headers: vec![
                ("Upgrade".to_string(), "h2c".to_string()),
                ("HTTP2-Settings".to_string(), "AAMAAABkAAQAAP__".to_string()),
                (
                    "Connection".to_string(),
                    "Upgrade, HTTP2-Settings".to_string(),
                ),
            ],
            method: "GET",
            body: None,
        });
        // A-6: WebSocket upgrade
        probes.push(Probe {
            class: ProbeClass::ProtocolMutation,
            channel: ProbeChannel::Header,
            description: "WebSocket upgrade probe",
            payload: "ws-upgrade-probe".to_string(),
            headers: vec![
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                (
                    "Sec-WebSocket-Key".to_string(),
                    "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
                ),
                ("Sec-WebSocket-Version".to_string(), "13".to_string()),
            ],
            method: "GET",
            body: None,
        });
        // A-7: Null byte in query
        probes.push(Probe {
            class: ProbeClass::EncodingBoundary,
            channel: ProbeChannel::Query,
            description: "Null byte in query string",
            payload: "q=%00injected".to_string(),
            headers: Vec::new(),
            method: "GET",
            body: None,
        });
        // A-8: Zero-width space in query
        probes.push(Probe {
            class: ProbeClass::EncodingBoundary,
            channel: ProbeChannel::Query,
            description: "Zero-width space in query token",
            payload: "q=safe%E2%80%8Bword".to_string(),
            headers: Vec::new(),
            method: "GET",
            body: None,
        });
        // A-14: TE.TE obfuscation
        probes.push(Probe {
            class: ProbeClass::ParserAmbiguity,
            channel: ProbeChannel::Header,
            description: "TE.TE obfuscation with duplicate Transfer-Encoding headers",
            payload: "te-te-obfuscation".to_string(),
            headers: vec![
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
                ("Transfer-encoding".to_string(), "cow".to_string()),
            ],
            method: "POST",
            body: Some("0\r\n\r\n".to_string()),
        });
        // A-15: TE obs-fold
        probes.push(Probe {
            class: ProbeClass::ParserAmbiguity,
            channel: ProbeChannel::Header,
            description: "Transfer-Encoding obsolete whitespace folding",
            payload: "te-obs-fold".to_string(),
            headers: vec![("Transfer-Encoding".to_string(), " chunked".to_string())],
            method: "POST",
            body: Some("0\r\n\r\n".to_string()),
        });
        // A-16: Hex IP in XFF
        probes.push(Probe {
            class: ProbeClass::EncodingBoundary,
            channel: ProbeChannel::Header,
            description: "Hex-format IP in X-Forwarded-For",
            payload: "xff-hex-ip".to_string(),
            headers: vec![("X-Forwarded-For".to_string(), "0x7F000001".to_string())],
            method: "GET",
            body: None,
        });
        // A-17: IPv6-mapped IPv4 in XFF
        probes.push(Probe {
            class: ProbeClass::EncodingBoundary,
            channel: ProbeChannel::Header,
            description: "IPv6-mapped IPv4 loopback in X-Forwarded-For",
            payload: "xff-ipv6-mapped".to_string(),
            headers: vec![(
                "X-Forwarded-For".to_string(),
                "::ffff:127.0.0.1".to_string(),
            )],
            method: "GET",
            body: None,
        });
        // A-18: Fat GET
        probes.push(Probe {
            class: ProbeClass::ParserAmbiguity,
            channel: ProbeChannel::Body,
            description: "GET request with body (fat GET)",
            payload: "fat-get-body".to_string(),
            headers: vec![("Content-Length".to_string(), "11".to_string())],
            method: "GET",
            body: Some("field1=test".to_string()),
        });
        // A-19: Prototype pollution in query
        probes.push(Probe {
            class: ProbeClass::SemanticDrift,
            channel: ProbeChannel::Query,
            description: "Prototype pollution keys in query string",
            payload: "__proto__[x]=y".to_string(),
            headers: Vec::new(),
            method: "GET",
            body: None,
        });
    }

    if tier >= 3 {
        probes.push(Probe {
            class: ProbeClass::BehavioralThrottle,
            channel: ProbeChannel::Method,
            description: "Burst timing probe",
            payload: "burst-3".to_string(),
            headers: Vec::new(),
            method: "GET",
            body: None,
        });
        probes.push(Probe {
            class: ProbeClass::ProtocolMutation,
            channel: ProbeChannel::Header,
            description: "Transfer encoding probe",
            payload: "chunked".to_string(),
            headers: vec![("Transfer-Encoding".to_string(), "chunked".to_string())],
            method: "POST",
            body: Some("0\r\n\r\n".to_string()),
        });
        probes.push(Probe {
            class: ProbeClass::ParserAmbiguity,
            channel: ProbeChannel::Header,
            description: "Content-Type boundary probe",
            payload: "multipart-boundary".to_string(),
            headers: vec![(
                "Content-Type".to_string(),
                "multipart/form-data; boundary=--wafprobe".to_string(),
            )],
            method: "POST",
            body: Some("--wafprobe\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--wafprobe--\r\n".to_string()),
        });
        probes.push(Probe {
            class: ProbeClass::BehavioralThrottle,
            channel: ProbeChannel::Header,
            description: "Rate control hint probe",
            payload: "rate-hint".to_string(),
            headers: vec![("X-Rate-Hint".to_string(), "1".to_string())],
            method: "GET",
            body: None,
        });
        // A-20: IBM037 charset declaration
        probes.push(Probe {
            class: ProbeClass::EncodingBoundary,
            channel: ProbeChannel::Header,
            description: "EBCDIC charset declaration (ibm037) to evade body inspection",
            payload: "charset-ibm037".to_string(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded; charset=ibm037".to_string(),
            )],
            method: "POST",
            body: Some("field1=test".to_string()),
        });
    }

    validate_zero_overlap(&probes)?;
    Ok(probes)
}

pub fn validate_zero_overlap(probes: &[Probe]) -> Result<()> {
    let allow_overlap = std::env::var("WAF_DETECTOR_ALLOW_SMOKE_OVERLAP")
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            value == "1" || value == "true" || value == "yes"
        })
        .unwrap_or(false);
    if allow_overlap {
        return Ok(());
    }

    let smoke_payloads = WafSmokeTest::payload_strings();
    let blacklist: HashSet<String> = smoke_payloads
        .into_iter()
        .map(|s| s.trim().to_lowercase())
        .collect();

    for probe in probes {
        let payload = probe.payload.trim().to_lowercase();
        if blacklist.contains(&payload) {
            return Err(anyhow!(
                "Probe payload overlaps smoke test payload: {}",
                probe.payload
            ));
        }
        for (_, value) in &probe.headers {
            let header_value = value.trim().to_lowercase();
            if blacklist.contains(&header_value) {
                return Err(anyhow!(
                    "Probe header overlaps smoke test payload: {}",
                    value
                ));
            }
        }
        if let Some(body) = &probe.body {
            let body_value = body.trim().to_lowercase();
            if blacklist.contains(&body_value) {
                return Err(anyhow!("Probe body overlaps smoke test payload: {}", body));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier1_catalog_has_multiple_probe_classes() {
        let probes = probe_catalog_for_tier(1).unwrap();
        let classes: HashSet<ProbeClass> = probes.iter().map(|probe| probe.class).collect();
        assert!(classes.contains(&ProbeClass::SemanticDrift));
        assert!(classes.contains(&ProbeClass::ProtocolMutation));
        assert!(classes.contains(&ProbeClass::EncodingBoundary));
        assert!(classes.contains(&ProbeClass::ResponseFingerprint));
    }

    #[test]
    fn tier2_catalog_adds_parser_ambiguity() {
        let probes = probe_catalog_for_tier(2).unwrap();
        assert!(probes
            .iter()
            .any(|probe| probe.class == ProbeClass::ParserAmbiguity));
        assert!(probes
            .iter()
            .any(|probe| probe.class == ProbeClass::ParserAmbiguity));
    }

    #[test]
    fn tier3_catalog_adds_behavioral_throttle() {
        let probes = probe_catalog_for_tier(3).unwrap();
        assert!(probes
            .iter()
            .any(|probe| probe.class == ProbeClass::BehavioralThrottle));
        assert!(probes
            .iter()
            .any(|probe| probe.class == ProbeClass::BehavioralThrottle));
    }

    #[test]
    fn all_probes_have_unique_payloads() {
        let probes = probe_catalog_for_tier(3).unwrap();
        let mut seen = HashSet::new();
        for probe in probes {
            assert!(seen.insert(probe.payload.clone()));
        }
    }

    #[test]
    fn tier1_has_xff_spoof_probe() {
        let probes = probe_catalog_for_tier(1).unwrap();
        assert!(probes.iter().any(|p| p.payload == "xff-loopback-spoof"));
    }

    #[test]
    fn tier2_has_path_override_probes() {
        let probes = probe_catalog_for_tier(2).unwrap();
        assert!(probes
            .iter()
            .any(|p| p.payload == "x-original-url-override"));
        assert!(probes.iter().any(|p| p.payload == "x-rewrite-url-override"));
    }

    #[test]
    fn tier2_has_upgrade_probes() {
        let probes = probe_catalog_for_tier(2).unwrap();
        assert!(probes.iter().any(|p| p.payload == "h2c-upgrade-probe"));
        assert!(probes.iter().any(|p| p.payload == "ws-upgrade-probe"));
    }

    #[test]
    fn tier1_has_method_override_probe() {
        let probes = probe_catalog_for_tier(1).unwrap();
        assert!(probes.iter().any(|p| p.payload == "method-override-delete"));
    }

    #[test]
    fn tier1_has_path_confusion_probes() {
        let probes = probe_catalog_for_tier(1).unwrap();
        assert!(probes.iter().any(|p| p.payload == "/admin%09"));
        assert!(probes
            .iter()
            .any(|p| p.payload == "/%3fadmin-path-confusion"));
    }

    #[test]
    fn tier1_has_geolocation_spoof_probe() {
        let probes = probe_catalog_for_tier(1).unwrap();
        assert!(probes.iter().any(|p| p.payload == "geo-header-spoof"));
    }

    #[test]
    fn tier2_has_te_obfuscation_probes() {
        let probes = probe_catalog_for_tier(2).unwrap();
        assert!(probes.iter().any(|p| p.payload == "te-te-obfuscation"));
        assert!(probes.iter().any(|p| p.payload == "te-obs-fold"));
    }

    #[test]
    fn tier2_has_hex_ip_probes() {
        let probes = probe_catalog_for_tier(2).unwrap();
        assert!(probes.iter().any(|p| p.payload == "xff-hex-ip"));
        assert!(probes.iter().any(|p| p.payload == "xff-ipv6-mapped"));
    }

    #[test]
    fn tier2_has_fat_get_probe() {
        let probes = probe_catalog_for_tier(2).unwrap();
        let fat = probes.iter().find(|p| p.payload == "fat-get-body");
        assert!(fat.is_some());
        let fat = fat.unwrap();
        assert_eq!(fat.method, "GET");
        assert!(fat.body.is_some());
    }

    #[test]
    fn tier3_has_ibm037_probe() {
        let probes = probe_catalog_for_tier(3).unwrap();
        assert!(probes.iter().any(|p| p.payload == "charset-ibm037"));
    }

    #[test]
    fn validator_rejects_smoke_payload_overlap() {
        let probes = vec![Probe {
            class: ProbeClass::SemanticDrift,
            channel: ProbeChannel::Query,
            description: "Overlap test",
            payload: "' OR '1'='1".to_string(),
            headers: Vec::new(),
            method: "GET",
            body: None,
        }];
        let err = validate_zero_overlap(&probes).unwrap_err();
        assert!(err.to_string().contains("overlaps smoke test"));
    }
}
