use crate::surface::{
    infer_priority, materialize_path_template, AuthClass, DiscoverySource, ParserTraits,
    SampleRequest, SurfaceEndpoint,
};
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub(crate) fn extract_openapi_endpoints(
    path: &Path,
    _target_base_url: &str,
) -> Result<Vec<SurfaceEndpoint>> {
    let raw = fs::read_to_string(path)?;
    let document = serde_json::from_str::<Value>(&raw)
        .or_else(|_| serde_yml::from_str::<Value>(&raw))
        .map_err(|err| anyhow!("failed to parse OpenAPI document {}: {err}", path.display()))?;

    let global_security = document.get("security");
    let mut endpoints = Vec::new();

    if let Some(paths) = document.get("paths").and_then(Value::as_object) {
        for (path_template, entry) in paths {
            let Some(operations) = entry.as_object() else {
                continue;
            };
            for (method, operation) in operations {
                if !is_http_method(method) {
                    continue;
                }
                let content_types = operation
                    .get("requestBody")
                    .and_then(|request_body| request_body.get("content"))
                    .and_then(Value::as_object)
                    .map(|content| content.keys().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                let mut tags = operation
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|tags| {
                        tags.iter()
                            .filter_map(Value::as_str)
                            .map(|value| value.to_string())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if path_template.to_ascii_lowercase().contains("graphql") {
                    tags.push("graphql".to_string());
                }
                let auth_class = operation
                    .get("security")
                    .or(global_security)
                    .map(security_to_auth_class)
                    .unwrap_or(AuthClass::Unknown);
                let parser_traits =
                    parser_traits_from_openapi(path_template, operation, &content_types);
                let query = build_sample_query(operation);
                let execution_path = materialize_path_template(path_template);

                endpoints.push(SurfaceEndpoint {
                    endpoint_id: String::new(),
                    path_template: path_template.clone(),
                    execution_path: execution_path.clone(),
                    methods: vec![method.to_ascii_uppercase()],
                    content_types: content_types.clone(),
                    auth_class,
                    parser_traits,
                    confidence: 0.92,
                    priority: infer_priority(
                        path_template,
                        &[method.to_ascii_uppercase()],
                        &tags,
                        auth_class,
                    ),
                    tags,
                    discovery_sources: vec![DiscoverySource::OpenApi],
                    sample_request: Some(SampleRequest {
                        method: method.to_ascii_uppercase(),
                        path: execution_path,
                        query,
                        content_type: content_types.first().cloned(),
                        body: sample_body(operation, &content_types),
                    }),
                    live_verification: None,
                    excluded: false,
                });
            }
        }
    }

    Ok(endpoints)
}

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
    )
}

fn security_to_auth_class(security: &Value) -> AuthClass {
    match security.as_array() {
        Some(entries) if entries.is_empty() => AuthClass::None,
        Some(_) => AuthClass::Required,
        None => AuthClass::Unknown,
    }
}

fn parser_traits_from_openapi(
    path_template: &str,
    operation: &Value,
    content_types: &[String],
) -> ParserTraits {
    let lower_content_types = content_types
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let query = operation
        .get("parameters")
        .and_then(Value::as_array)
        .map(|parameters| {
            parameters.iter().any(|parameter| {
                parameter
                    .get("in")
                    .and_then(Value::as_str)
                    .map(|location| location == "query")
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    ParserTraits {
        json: lower_content_types
            .iter()
            .any(|value| value.contains("json")),
        form: lower_content_types
            .iter()
            .any(|value| value.contains("application/x-www-form-urlencoded")),
        multipart: lower_content_types
            .iter()
            .any(|value| value.contains("multipart")),
        graphql: path_template.to_ascii_lowercase().contains("graphql")
            || lower_content_types
                .iter()
                .any(|value| value.contains("graphql")),
        query,
        header_sensitive: operation
            .get("parameters")
            .and_then(Value::as_array)
            .map(|parameters| {
                parameters.iter().any(|parameter| {
                    parameter
                        .get("in")
                        .and_then(Value::as_str)
                        .map(|location| location == "header")
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false),
        same_origin_api: path_template.starts_with("/api/"),
        dynamic_segments: path_template.contains('{'),
    }
}

fn build_sample_query(operation: &Value) -> Option<String> {
    let mut parts = Vec::new();
    let parameters = operation.get("parameters")?.as_array()?;
    for parameter in parameters {
        if parameter.get("in").and_then(Value::as_str) != Some("query") {
            continue;
        }
        let name = parameter.get("name").and_then(Value::as_str)?;
        parts.push(format!("{name}=test"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("&"))
    }
}

fn sample_body(operation: &Value, content_types: &[String]) -> Option<String> {
    if !content_types
        .iter()
        .any(|content_type| content_type.to_ascii_lowercase().contains("json"))
    {
        return None;
    }

    let schema = operation
        .get("requestBody")
        .and_then(|request_body| request_body.get("content"))
        .and_then(|content| content.get("application/json"))
        .and_then(|entry| entry.get("schema"));
    let properties = schema
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)?;

    let body = properties
        .keys()
        .map(|key| (key.clone(), Value::String("sample".to_string())))
        .collect::<serde_json::Map<_, _>>();
    Some(Value::Object(body).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_extract_openapi_endpoints_builds_route_metadata() {
        let tempdir = TempDir::new().expect("tempdir");
        let spec_path = tempdir.path().join("openapi.yaml");
        fs::write(
            &spec_path,
            r#"
openapi: 3.1.0
paths:
  /api/tokenize:
    post:
      security:
        - bearerAuth: []
      tags: [tokenization]
      parameters:
        - in: query
          name: tenant
          schema:
            type: string
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                value:
                  type: string
"#,
        )
        .unwrap();

        let endpoints = extract_openapi_endpoints(&spec_path, "https://example.com").unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path_template, "/api/tokenize");
        assert_eq!(endpoints[0].auth_class, AuthClass::Required);
        assert!(endpoints[0].parser_traits.json);
        assert_eq!(
            endpoints[0]
                .sample_request
                .as_ref()
                .and_then(|request| request.query.as_deref()),
            Some("tenant=test")
        );
    }
}
