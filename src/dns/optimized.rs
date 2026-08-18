use crate::DnsInfo;
use anyhow::Result;
use hickory_resolver::config::{ResolverConfig, GOOGLE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DnsResolver {
    resolver: Arc<TokioResolver>,
}

impl DnsResolver {
    pub fn new() -> Result<Self> {
        // hickory-resolver 0.26 replaced `TokioAsyncResolver::tokio` with a
        // builder, and `ResolverConfig::google()` with the `GOOGLE` server
        // group. `udp_and_tcp` preserves 0.24's `google()` behavior (UDP with
        // TCP fallback against Google Public DNS).
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&GOOGLE),
            TokioRuntimeProvider::default(),
        )
        .build()?;
        Ok(Self {
            resolver: Arc::new(resolver),
        })
    }

    pub async fn resolve(&self, domain: &str) -> Result<DnsInfo> {
        let mut info = DnsInfo::default();

        // Clean domain (remove protocol if present)
        let domain = domain
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(domain);

        // Resolve CNAMEs (critical for CDN/WAF detection)
        if let Ok(lookup) = self.resolver.lookup_ip(domain).await {
            // Get IP addresses (A records)
            for ip in lookup.iter() {
                info.a_records.push(ip.to_string());
            }
        }

        // Explicitly look for CNAME records
        // Note: hickory-resolver aut-follows CNAMEs for lookup_ip, checking canonical name
        // We'll try a specific query for CNAMEs to get the chain if possible,
        // essentially we want to know "is this pointing to cloudflare?"

        use hickory_resolver::proto::rr::RecordType;
        match self.resolver.lookup(domain, RecordType::CNAME).await {
            Ok(lookup) => {
                // hickory-resolver 0.26 dropped `Lookup::iter()` over record
                // data; walk `answers()` and match the record type instead.
                for record in lookup.answers() {
                    if let RData::CNAME(cname) = &record.data {
                        info.cnames.push(cname.to_string());
                    }
                }
            }
            Err(_) => {
                // If it fails, it might be because it's an A record directly, or CNAME at root (rare/flattened)
                // We'll rely on the IP lookup triggering standard resolution
            }
        }

        // Also get TXT records (sometimes used for verification)
        if let Ok(lookup) = self.resolver.txt_lookup(domain).await {
            for record in lookup.answers() {
                if let RData::TXT(txt) = &record.data {
                    for data in txt.txt_data.iter() {
                        info.txt_records
                            .push(String::from_utf8_lossy(data).to_string());
                    }
                }
            }
        }

        // Get NS records (often reveals provider)
        if let Ok(lookup) = self.resolver.ns_lookup(domain).await {
            for record in lookup.answers() {
                if let RData::NS(ns) = &record.data {
                    info.ns_records.push(ns.to_string());
                }
            }
        }

        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Network-dependent, so `#[ignore]`d for offline/CI runs. Run with
    /// `cargo test --lib dns::optimized -- --ignored`.
    ///
    /// This is the only coverage of the record-extraction path: `resolve()`'s
    /// CNAME/TXT/NS arms had to be rewritten by hand for hickory-resolver 0.26
    /// (which dropped `Lookup::iter()` in favor of `answers()` plus an `RData`
    /// match), and an incorrect match arm fails silently as an empty vec
    /// rather than a compile error.
    #[tokio::test]
    #[ignore = "requires network access to 8.8.8.8"]
    async fn resolve_populates_records_for_a_cdn_fronted_host() {
        let resolver = DnsResolver::new().expect("resolver");
        let info = resolver
            .resolve("www.adobe.com")
            .await
            .expect("resolution succeeds");

        assert!(!info.a_records.is_empty(), "expected A records");
        assert!(
            !info.cnames.is_empty(),
            "expected a CNAME chain for a CDN-fronted host, got {:?}",
            info.cnames
        );
    }
}
