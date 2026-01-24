use crate::DnsInfo;
use anyhow::Result;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DnsResolver {
    resolver: Arc<TokioAsyncResolver>,
}

impl DnsResolver {
    pub fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default());
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
                for cname in lookup.iter() {
                    info.cnames.push(cname.to_string());
                }
            }
            Err(_) => {
                // If it fails, it might be because it's an A record directly, or CNAME at root (rare/flattened)
                // We'll rely on the IP lookup triggering standard resolution
            }
        }

        // Also get TXT records (sometimes used for verification)
        if let Ok(lookup) = self.resolver.txt_lookup(domain).await {
            for txt in lookup.iter() {
                for data in txt.txt_data() {
                    info.txt_records
                        .push(String::from_utf8_lossy(data).to_string());
                }
            }
        }

        // Get NS records (often reveals provider)
        if let Ok(lookup) = self.resolver.ns_lookup(domain).await {
            for ns in lookup.iter() {
                info.ns_records.push(ns.to_string());
            }
        }

        Ok(info)
    }
}
