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
