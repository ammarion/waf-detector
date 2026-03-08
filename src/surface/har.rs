use crate::surface::{
    infer_priority, materialize_path_template, AuthClass, DiscoverySource, ParserTraits,
    SampleRequest, SurfaceEndpoint,
};
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::fs;
use std::path::Path;
use url::Url;

pub(crate) fn extract_har_endpoints(
    path: &Path,
    target_base_url: &str,
) -> Result<Vec<SurfaceEndpoint>> {
    let raw = fs::read_to_string(path)?;
    let document = serde_json::from_str::<Value>(&raw)
        .map_err(|err| anyhow!("failed to parse HAR {}: {err}", path.display()))?;
    let mut endpoints = Vec::new();

    let entries = document
        .get("log")
        .and_then(|log| log.get("entries"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for entry in entries {
        let Some(request) = entry.get("request") else {
            continue;
        };
        let Some(method) = request.get("method").and_then(Value::as_str) else {
            continue;
        };
        let Some(raw_url) = request.get("url").and_then(Value::as_str) else {
            continue;
        };
        let parsed = match Url::parse(raw_url)
            .or_else(|_| Url::parse(&format!("{target_base_url}{raw_url}")))
        {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        let path_template = if parsed.path().is_empty() {
            "/".to_string()
        } else {
            parsed.path().to_string()
        };
        let query = parsed.query().map(|value| value.to_string());
        let headers = request
            .get("headers")
            .and_then(Value::as_array)
            .map(|headers| {
                headers
                    .iter()
                    .filter_map(|header| {
                        Some((
                            header.get("name")?.as_str()?.to_string(),
                            header.get("value")?.as_str()?.to_string(),
                        ))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let content_type = request
            .get("postData")
            .and_then(|post_data| post_data.get("mimeType"))
            .and_then(Value::as_str)
            .map(|value| value.to_string())
            .or_else(|| {
                headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                    .map(|(_, value)| value.clone())
            });
        let auth_class = if headers.iter().any(|(name, _)| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "authorization" | "cookie" | "x-api-key"
            )
        }) {
            AuthClass::Required
        } else {
            AuthClass::Unknown
        };
        let parser_traits = ParserTraits {
            json: content_type
                .as_ref()
                .map(|value| value.to_ascii_lowercase().contains("json"))
                .unwrap_or(false),
            form: content_type
                .as_ref()
                .map(|value| {
                    value
                        .to_ascii_lowercase()
                        .contains("application/x-www-form-urlencoded")
                })
                .unwrap_or(false),
            multipart: content_type
                .as_ref()
                .map(|value| value.to_ascii_lowercase().contains("multipart"))
                .unwrap_or(false),
            graphql: path_template.to_ascii_lowercase().contains("graphql"),
            query: query.is_some(),
            header_sensitive: headers.iter().any(|(name, _)| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "x-forwarded-for"
                        | "x-forwarded-host"
                        | "x-http-method-override"
                        | "x-original-url"
                )
            }),
            same_origin_api: path_template.starts_with("/api/"),
            dynamic_segments: path_template.contains('{') || path_template.contains(':'),
        };
        let mut content_types = Vec::new();
        if let Some(content_type) = &content_type {
            content_types.push(content_type.clone());
        }
        let mut tags = Vec::new();
        if parser_traits.graphql {
            tags.push("graphql".to_string());
        }

        endpoints.push(SurfaceEndpoint {
            endpoint_id: String::new(),
            path_template: path_template.clone(),
            execution_path: materialize_path_template(&path_template),
            methods: vec![method.to_ascii_uppercase()],
            content_types,
            auth_class,
            parser_traits,
            confidence: 0.78,
            priority: infer_priority(
                &path_template,
                &[method.to_ascii_uppercase()],
                &tags,
                auth_class,
            ),
            tags,
            discovery_sources: vec![DiscoverySource::Har],
            sample_request: Some(SampleRequest {
                method: method.to_ascii_uppercase(),
                path: path_template.clone(),
                query,
                content_type,
                body: request
                    .get("postData")
                    .and_then(|post_data| post_data.get("text"))
                    .and_then(Value::as_str)
                    .map(|value| value.to_string()),
            }),
            live_verification: None,
            excluded: false,
        });
    }

    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_extract_har_endpoints_uses_authenticated_requests_as_signal() {
        let tempdir = TempDir::new().expect("tempdir");
        let har_path = tempdir.path().join("traffic.har");
        fs::write(
            &har_path,
            r#"{
  "log": {
    "entries": [
      {
        "request": {
          "method": "POST",
          "url": "https://api.example.com/api/tokenize?tenant=acme",
          "headers": [
            { "name": "Authorization", "value": "Bearer secret" },
            { "name": "Content-Type", "value": "application/json" }
          ],
          "postData": {
            "mimeType": "application/json",
            "text": "{\"value\":\"secret\"}"
          }
        }
      }
    ]
  }
}"#,
        )
        .unwrap();

        let endpoints = extract_har_endpoints(&har_path, "https://app.example.com").unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].auth_class, AuthClass::Required);
        assert!(endpoints[0].parser_traits.json);
        assert_eq!(
            endpoints[0]
                .sample_request
                .as_ref()
                .unwrap()
                .query
                .as_deref(),
            Some("tenant=acme")
        );
    }
}
