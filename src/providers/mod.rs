pub mod cloudflare;
pub mod akamai;
pub mod aws;
pub mod fastly;
pub mod vercel;

use crate::{DetectionContext, Evidence, http::HttpClient, ProviderType, DetectionProvider};
use anyhow::Result;

/// Provider enum to solve async trait object issue
#[derive(Debug, Clone)]
pub enum Provider {
    CloudFlare(cloudflare::CloudFlareProvider),
    Akamai(akamai::AkamaiProvider),
    AWS(aws::AwsProvider),
    Fastly(fastly::FastlyProvider),
    Vercel(vercel::VercelProvider),
}

impl Provider {
    pub fn name(&self) -> &str {
        match self {
            Provider::CloudFlare(p) => p.name(),
            Provider::Akamai(p) => p.name(),
            Provider::AWS(p) => p.name(),
            Provider::Fastly(p) => p.name(),
            Provider::Vercel(p) => p.name(),
        }
    }

    pub fn version(&self) -> &str {
        match self {
            Provider::CloudFlare(p) => p.version(),
            Provider::Akamai(p) => p.version(),
            Provider::AWS(p) => p.version(),
            Provider::Fastly(p) => p.version(),
            Provider::Vercel(p) => p.version(),
        }
    }

    pub fn description(&self) -> Option<String> {
        match self {
            Provider::CloudFlare(p) => p.description(),
            Provider::Akamai(p) => p.description(),
            Provider::AWS(p) => p.description(),
            Provider::Fastly(p) => p.description(),
            Provider::Vercel(p) => p.description(),
        }
    }

    pub fn provider_type(&self) -> ProviderType {
        match self {
            Provider::CloudFlare(p) => p.provider_type(),
            Provider::Akamai(p) => p.provider_type(),
            Provider::AWS(p) => p.provider_type(),
            Provider::Fastly(p) => p.provider_type(),
            Provider::Vercel(p) => p.provider_type(),
        }
    }

    pub fn confidence_base(&self) -> f64 {
        match self {
            Provider::CloudFlare(p) => p.confidence_base(),
            Provider::Akamai(p) => p.confidence_base(),
            Provider::AWS(p) => p.confidence_base(),
            Provider::Fastly(p) => p.confidence_base(),
            Provider::Vercel(p) => p.confidence_base(),
        }
    }

    pub fn priority(&self) -> u32 {
        match self {
            Provider::CloudFlare(p) => p.priority(),
            Provider::Akamai(p) => p.priority(),
            Provider::AWS(p) => p.priority(),
            Provider::Fastly(p) => p.priority(),
            Provider::Vercel(p) => p.priority(),
        }
    }

    pub fn enabled(&self) -> bool {
        match self {
            Provider::CloudFlare(p) => p.enabled(),
            Provider::Akamai(p) => p.enabled(),
            Provider::AWS(p) => p.enabled(),
            Provider::Fastly(p) => p.enabled(),
            Provider::Vercel(p) => p.enabled(),
        }
    }

    pub async fn detect(&self, context: &DetectionContext) -> Result<Vec<Evidence>> {
        match self {
            Provider::CloudFlare(p) => p.detect(context).await,
            Provider::Akamai(p) => p.detect(context).await,
            Provider::AWS(p) => p.detect(context).await,
            Provider::Fastly(p) => p.detect(context).await,
            Provider::Vercel(p) => p.detect(context).await,
        }
    }

    pub async fn passive_detect(&self, response: &crate::http::HttpResponse) -> Result<Vec<Evidence>> {
        match self {
            Provider::CloudFlare(p) => p.passive_detect(response).await,
            Provider::Akamai(p) => p.passive_detect(response).await,
            Provider::AWS(p) => p.passive_detect(response).await,
            Provider::Fastly(p) => p.passive_detect(response).await,
            Provider::Vercel(p) => p.passive_detect(response).await,
        }
    }

    pub async fn active_detect(&self, client: &HttpClient, url: &str) -> Result<Vec<Evidence>> {
        match self {
            Provider::CloudFlare(p) => p.active_detect(client, url).await,
            Provider::Akamai(p) => p.active_detect(client, url).await,
            Provider::AWS(p) => p.active_detect(client, url).await,
            Provider::Fastly(p) => p.active_detect(client, url).await,
            Provider::Vercel(p) => p.active_detect(client, url).await,
        }
    }
}

/// Provider metadata for listing
#[derive(Debug, Clone)]
pub struct ProviderMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub provider_type: String,
    pub enabled: bool,
    pub priority: u32,
}

impl From<&Provider> for ProviderMetadata {
    fn from(provider: &Provider) -> Self {
        Self {
            name: provider.name().to_string(),
            version: provider.version().to_string(),
            description: provider.description(),
            provider_type: match provider.provider_type() {
                ProviderType::WAF => "WAF Only".to_string(),
                ProviderType::CDN => "CDN Only".to_string(),
                ProviderType::Both => "Both".to_string(),
            },
            enabled: provider.enabled(),
            priority: provider.priority(),
        }
    }
}
