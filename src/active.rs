use crate::effectiveness::consent::{ConsentManager, ScopeTarget, TargetClass};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use url::Url;

pub const ACTIVE_TARGET_PROFILE_ENV: &str = "WAF_DETECTOR_ACTIVE_TARGET_PROFILE";
pub const OPERATOR_ID_ENV: &str = "WAF_DETECTOR_OPERATOR";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActiveTargetProfile {
    #[default]
    Public,
    Internal,
}

impl ActiveTargetProfile {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "public" => Ok(Self::Public),
            "internal" => Ok(Self::Internal),
            other => Err(anyhow!(
                "invalid active target profile '{other}' (expected public|internal)"
            )),
        }
    }

    pub fn from_env() -> Self {
        std::env::var(ACTIVE_TARGET_PROFILE_ENV)
            .ok()
            .and_then(|value| Self::parse(&value).ok())
            .unwrap_or_default()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub original_url: String,
    pub normalized_url: String,
    pub host: String,
    pub port: u16,
    pub registered_target: ScopeTarget,
    pub active_target_profile: ActiveTargetProfile,
    pub resolved_ips: Vec<IpAddr>,
    pub pinned_ip: IpAddr,
}

impl ResolvedTarget {
    pub fn resolved_ip_strings(&self) -> Vec<String> {
        self.resolved_ips.iter().map(ToString::to_string).collect()
    }

    pub fn with_url(&self, url: &str) -> Result<Self> {
        let normalized_url = normalize_target_url(url)?;
        let parsed = Url::parse(&normalized_url)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("target URL is missing a host"))?
            .to_ascii_lowercase();
        if host != self.host {
            return Err(anyhow!(
                "cannot change resolved target host from {} to {}",
                self.host,
                host
            ));
        }

        Ok(Self {
            original_url: url.to_string(),
            normalized_url,
            host: self.host.clone(),
            port: parsed.port_or_known_default().unwrap_or(self.port),
            registered_target: self.registered_target.clone(),
            active_target_profile: self.active_target_profile,
            resolved_ips: self.resolved_ips.clone(),
            pinned_ip: self.pinned_ip,
        })
    }
}

pub fn current_operator_id() -> String {
    std::env::var(OPERATOR_ID_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("USER")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            std::env::var("USERNAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| "unknown-operator".to_string())
}

/// Resolve and authorize a target URL in one step. Creates a ConsentManager,
/// checks consent, and returns the resolved target. Use for single-target flows.
pub fn resolve_authorized_target(url: &str) -> Result<ResolvedTarget> {
    let consent = ConsentManager::new();
    guard_target(&consent, url)
}

pub fn guard_target(consent_manager: &ConsentManager, target_url: &str) -> Result<ResolvedTarget> {
    guard_target_with_profile(consent_manager, target_url, ActiveTargetProfile::from_env())
}

pub fn guard_target_with_profile(
    consent_manager: &ConsentManager,
    target_url: &str,
    profile: ActiveTargetProfile,
) -> Result<ResolvedTarget> {
    let normalized_url = normalize_target_url(target_url)?;
    let parsed = Url::parse(&normalized_url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("target URL is missing a host"))?
        .to_ascii_lowercase();
    let port = parsed.port_or_known_default().unwrap_or(443);

    let registered_target = consent_manager
        .match_target(&normalized_url)?
        .unwrap_or_else(|| ScopeTarget {
            host: host.clone(),
            class: TargetClass::Public,
        });

    if registered_target.class == TargetClass::Internal && profile != ActiveTargetProfile::Internal
    {
        return Err(anyhow!(
            "Target {} is registered as internal. Re-run with `--active-target-profile internal`.",
            registered_target.host
        ));
    }

    let resolved_ips = resolve_host(&host, port)?;
    let pinned_ip = *resolved_ips
        .first()
        .ok_or_else(|| anyhow!("DNS resolution returned no addresses for {}", host))?;

    for ip in &resolved_ips {
        validate_ip_for_target(ip, registered_target.class, profile)?;
    }

    Ok(ResolvedTarget {
        original_url: target_url.to_string(),
        normalized_url,
        host,
        port,
        registered_target,
        active_target_profile: profile,
        resolved_ips,
        pinned_ip,
    })
}

pub fn normalize_target_url(target_url: &str) -> Result<String> {
    Url::parse(target_url)
        .or_else(|_| Url::parse(&format!("https://{target_url}")))
        .map(|url| url.to_string())
        .map_err(|err| anyhow!("invalid target URL '{target_url}': {err}"))
}

fn resolve_host(host: &str, port: u16) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let socket_addrs: Vec<_> = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|err| anyhow!("DNS resolution failed for {host}: {err}"))?
        .collect();

    if socket_addrs.is_empty() {
        return Err(anyhow!("DNS resolution returned no addresses for {host}"));
    }

    let mut resolved_ips = Vec::new();
    for addr in socket_addrs {
        if !resolved_ips.contains(&addr.ip()) {
            resolved_ips.push(addr.ip());
        }
    }

    Ok(resolved_ips)
}

fn validate_ip_for_target(
    ip: &IpAddr,
    registered_class: TargetClass,
    profile: ActiveTargetProfile,
) -> Result<()> {
    let classification = classify_ip(ip);

    if classification == IpClassification::Metadata {
        return Err(anyhow!("target resolves to metadata endpoint IP {}", ip));
    }

    match profile {
        ActiveTargetProfile::Public => {
            if classification != IpClassification::Public {
                return Err(anyhow!(
                    "public active target profile rejects {} ({})",
                    ip,
                    classification.description()
                ));
            }
        }
        ActiveTargetProfile::Internal => {
            if classification.is_always_blocked_internal() {
                return Err(anyhow!(
                    "internal active target profile rejects {} ({})",
                    ip,
                    classification.description()
                ));
            }
        }
    }

    if registered_class == TargetClass::Public && classification != IpClassification::Public {
        return Err(anyhow!(
            "target resolves to {} ({}), but it is registered as a public target. Register it with `--scope init <domain> --internal` and use `--active-target-profile internal`.",
            ip,
            classification.description()
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpClassification {
    Public,
    Private,
    CarrierNat,
    LinkLocal,
    Loopback,
    Unspecified,
    Multicast,
    Reserved,
    Documentation,
    Benchmark,
    Metadata,
}

impl IpClassification {
    fn description(self) -> &'static str {
        match self {
            Self::Public => "public address",
            Self::Private => "private address space",
            Self::CarrierNat => "carrier-grade NAT address space",
            Self::LinkLocal => "link-local address space",
            Self::Loopback => "loopback address space",
            Self::Unspecified => "unspecified address space",
            Self::Multicast => "multicast address space",
            Self::Reserved => "reserved address space",
            Self::Documentation => "documentation/test address space",
            Self::Benchmark => "benchmark address space",
            Self::Metadata => "cloud metadata endpoint",
        }
    }

    fn is_always_blocked_internal(self) -> bool {
        matches!(
            self,
            Self::Loopback
                | Self::Unspecified
                | Self::Multicast
                | Self::Metadata
                | Self::LinkLocal
                | Self::Documentation
                | Self::Benchmark
                | Self::Reserved
        )
    }
}

fn classify_ip(ip: &IpAddr) -> IpClassification {
    match ip {
        IpAddr::V4(ipv4) => classify_ipv4(*ipv4),
        IpAddr::V6(ipv6) => classify_ipv6(*ipv6),
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> IpClassification {
    let octets = ip.octets();

    if ip == Ipv4Addr::new(169, 254, 169, 254) {
        return IpClassification::Metadata;
    }
    if ip.is_loopback() {
        return IpClassification::Loopback;
    }
    if ip.is_private() {
        return IpClassification::Private;
    }
    if ip.is_link_local() {
        return IpClassification::LinkLocal;
    }
    if ip.is_multicast() || (octets[0] >= 224 && octets[0] <= 239) {
        return IpClassification::Multicast;
    }
    if ip.is_unspecified() || octets[0] == 0 {
        return IpClassification::Unspecified;
    }
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return IpClassification::CarrierNat;
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return IpClassification::Reserved;
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return IpClassification::Documentation;
    }
    if octets[0] == 198 && octets[1] == 18 || octets[0] == 198 && octets[1] == 19 {
        return IpClassification::Benchmark;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return IpClassification::Documentation;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return IpClassification::Documentation;
    }
    if octets[0] >= 240 {
        return IpClassification::Reserved;
    }

    IpClassification::Public
}

fn classify_ipv6(ip: Ipv6Addr) -> IpClassification {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_ipv4(v4);
    }

    if ip == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) {
        return IpClassification::Metadata;
    }
    if ip.is_loopback() {
        return IpClassification::Loopback;
    }
    if ip.is_unspecified() {
        return IpClassification::Unspecified;
    }
    if ip.is_multicast() {
        return IpClassification::Multicast;
    }
    if ip.is_unique_local() {
        return IpClassification::Private;
    }
    if ip.is_unicast_link_local() || (ip.segments()[0] & 0xffc0) == 0xfe80 {
        return IpClassification::LinkLocal;
    }
    if ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8 {
        return IpClassification::Documentation;
    }

    IpClassification::Public
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effectiveness::consent::{ConsentManager, TargetClass};
    use tempfile::TempDir;

    fn with_temp_home<F>(f: F)
    where
        F: FnOnce(),
    {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("WAF_DETECTOR_HOME").ok();
        let temp_dir = TempDir::new().expect("temp dir");
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());
        f();
        if let Some(home) = original_home {
            std::env::set_var("WAF_DETECTOR_HOME", home);
        } else {
            std::env::remove_var("WAF_DETECTOR_HOME");
        }
    }

    #[test]
    fn test_profile_parse() {
        assert_eq!(
            ActiveTargetProfile::parse("public").expect("public profile"),
            ActiveTargetProfile::Public
        );
        assert_eq!(
            ActiveTargetProfile::parse("internal").expect("internal profile"),
            ActiveTargetProfile::Internal
        );
        assert!(ActiveTargetProfile::parse("nope").is_err());
    }

    #[test]
    fn test_ipv4_classification() {
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            IpClassification::Public
        );
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            IpClassification::Private
        );
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            IpClassification::CarrierNat
        );
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
            IpClassification::Metadata
        );
    }

    #[test]
    fn test_ipv6_classification() {
        assert_eq!(
            classify_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)),
            IpClassification::Loopback
        );
        assert_eq!(
            classify_ip(&IpAddr::V6("fc00::1".parse().expect("ula"))),
            IpClassification::Private
        );
        assert_eq!(
            classify_ip(&IpAddr::V6("2001:db8::1".parse().expect("doc"))),
            IpClassification::Documentation
        );
    }

    #[test]
    fn test_internal_targets_require_internal_runtime_profile() {
        with_temp_home(|| {
            let consent_manager = ConsentManager::new();
            consent_manager
                .set_authorized_targets_with_class(
                    &["10.0.0.10".to_string()],
                    TargetClass::Internal,
                )
                .expect("internal target should be registered");

            let err = guard_target_with_profile(
                &consent_manager,
                "https://10.0.0.10",
                ActiveTargetProfile::Public,
            )
            .expect_err("public runtime profile should reject internal targets");
            assert!(err.to_string().contains("registered as internal"));

            let target = guard_target_with_profile(
                &consent_manager,
                "https://10.0.0.10",
                ActiveTargetProfile::Internal,
            )
            .expect("internal runtime profile should allow registered internal targets");
            assert_eq!(target.pinned_ip, "10.0.0.10".parse::<IpAddr>().unwrap());
            assert_eq!(target.active_target_profile, ActiveTargetProfile::Internal);
        });
    }
}
