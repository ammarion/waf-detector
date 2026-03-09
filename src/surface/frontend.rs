use crate::surface::{
    infer_priority, materialize_path_template, normalize_relative_or_absolute_path, AuthClass,
    DiscoverySource, ParserTraits, RoutePriority, SampleRequest, SurfaceEndpoint,
};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tree_sitter::{Node, Parser, TreeCursor};

pub(crate) fn extract_frontend_endpoints(
    repo_path: &Path,
    target_base_url: &str,
) -> Result<Vec<SurfaceEndpoint>> {
    let mut files = Vec::new();
    collect_repo_files(repo_path, &mut files)?;

    let mut endpoints = Vec::new();
    for file in files {
        let source = fs::read_to_string(&file)?;
        if let Some(route_endpoint) = extract_same_origin_handler(&file, repo_path, &source) {
            endpoints.push(route_endpoint);
        }
        let Some(language) = language_for_path(&file) else {
            continue;
        };
        let mut parser = Parser::new();
        parser.set_language(&language).map_err(|err| {
            anyhow::anyhow!("failed to initialize parser for {}: {err}", file.display())
        })?;
        let Some(tree) = parser.parse(&source, None) else {
            continue;
        };
        let mut variables = HashMap::new();
        collect_string_variables(tree.root_node(), &source, &mut variables);
        collect_endpoints(
            tree.root_node(),
            &source,
            &variables,
            target_base_url,
            &mut endpoints,
        );
        if let Some(endpoint) = graphql_endpoint_from_source(&source) {
            endpoints.push(endpoint);
        }
    }

    Ok(endpoints)
}

fn collect_repo_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if entry.file_type()?.is_dir() {
            if matches!(
                file_name.as_ref(),
                "node_modules" | ".git" | ".next" | "dist" | "build" | "coverage"
            ) {
                continue;
            }
            collect_repo_files(&entry_path, files)?;
            continue;
        }

        if matches!(
            entry_path.extension().and_then(|ext| ext.to_str()),
            Some("js" | "jsx" | "ts" | "tsx")
        ) {
            files.push(entry_path);
        }
    }
    Ok(())
}

fn language_for_path(path: &Path) -> Option<tree_sitter::Language> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("js") | Some("jsx") => Some(tree_sitter_javascript::LANGUAGE.into()),
        Some("ts") => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Some("tsx") => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => None,
    }
}

fn collect_string_variables(node: Node<'_>, source: &str, variables: &mut HashMap<String, String>) {
    if node.kind() == "variable_declarator" {
        if let (Some(name), Some(value)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        ) {
            if name.kind() == "identifier" {
                let variable_name = node_text(name, source);
                if value.kind() == "object" {
                    collect_object_string_members(&variable_name, value, source, variables);
                } else if let Some(resolved) = resolve_string_expression(value, source, variables) {
                    variables.insert(variable_name, resolved);
                }
            }
        }
    }
    if node.kind() == "function_declaration" {
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                if let Some(resolved) = resolve_function_return_string(node, source, variables) {
                    variables.insert(node_text(name, source), resolved);
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_string_variables(child, source, variables);
    }
}

fn collect_object_string_members(
    prefix: &str,
    node: Node<'_>,
    source: &str,
    variables: &mut HashMap<String, String>,
) {
    if node.kind() != "object" {
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "pair" {
            continue;
        }
        let Some(key_node) = child
            .child_by_field_name("key")
            .or_else(|| child.named_child(0))
        else {
            continue;
        };
        let Some(value_node) = child
            .child_by_field_name("value")
            .or_else(|| child.named_child(1))
        else {
            continue;
        };

        let key_name = normalize_object_key(&node_text(key_node, source));
        let qualified_key = format!("{prefix}.{key_name}");
        if value_node.kind() == "object" {
            collect_object_string_members(&qualified_key, value_node, source, variables);
            continue;
        }
        if let Some(resolved) = resolve_string_expression(value_node, source, variables) {
            variables.insert(qualified_key, resolved);
        }
    }
}

fn resolve_function_return_string(
    node: Node<'_>,
    source: &str,
    variables: &HashMap<String, String>,
) -> Option<String> {
    let body = node.child_by_field_name("body")?;
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if child.kind() != "return_statement" {
            continue;
        }
        if let Some(argument) = child.named_child(0) {
            if let Some(resolved) = resolve_string_expression(argument, source, variables) {
                return Some(resolved);
            }
        }
    }
    None
}

fn normalize_object_key(value: &str) -> String {
    strip_quotes(value)
        .trim_matches(|c| c == '[' || c == ']')
        .to_string()
}

fn collect_endpoints(
    node: Node<'_>,
    source: &str,
    variables: &HashMap<String, String>,
    target_base_url: &str,
    endpoints: &mut Vec<SurfaceEndpoint>,
) {
    if node.kind() == "call_expression" {
        if let Some(endpoint) = endpoint_from_call(node, source, variables, target_base_url) {
            endpoints.push(endpoint);
        }
    }
    if node.kind() == "tagged_template" {
        if let Some(endpoint) = endpoint_from_graphql_template(node, source) {
            endpoints.push(endpoint);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_endpoints(child, source, variables, target_base_url, endpoints);
    }
}

fn endpoint_from_call(
    node: Node<'_>,
    source: &str,
    variables: &HashMap<String, String>,
    target_base_url: &str,
) -> Option<SurfaceEndpoint> {
    let function = node.child_by_field_name("function")?;
    let arguments = node.child_by_field_name("arguments")?;
    let args = named_children(arguments);
    let callee = node_text(function, source);

    if callee == "fetch" {
        let url = args
            .first()
            .and_then(|arg| resolve_string_expression(*arg, source, variables))?;
        let options = args
            .get(1)
            .and_then(|arg| parse_request_options(*arg, source, variables))
            .unwrap_or_default();
        let method = options
            .get("method")
            .cloned()
            .unwrap_or_else(|| "GET".to_string());
        return build_endpoint_from_request(
            &method,
            &url,
            options.get("body").cloned(),
            extract_headers(&options),
            target_base_url,
            DiscoverySource::FrontendRepo,
        );
    }

    if callee == "axios" || callee.ends_with(".request") {
        let config = args
            .first()
            .and_then(|arg| parse_request_options(*arg, source, variables))?;
        let url = config.get("url")?.clone();
        let method = config
            .get("method")
            .cloned()
            .unwrap_or_else(|| "GET".to_string());
        return build_endpoint_from_request(
            &method,
            &url,
            config.get("body").cloned(),
            extract_headers(&config),
            target_base_url,
            DiscoverySource::FrontendRepo,
        );
    }

    if let Some(method) = axios_method_from_callee(&callee) {
        let url = args
            .first()
            .and_then(|arg| resolve_string_expression(*arg, source, variables))?;
        let config = args
            .iter()
            .skip(1)
            .find_map(|arg| parse_request_options(*arg, source, variables))
            .unwrap_or_default();
        let body = if matches!(method, "POST" | "PUT" | "PATCH") {
            args.get(1)
                .and_then(|arg| resolve_request_body(*arg, source, variables))
                .or_else(|| config.get("body").cloned())
        } else {
            config.get("body").cloned()
        };
        return build_endpoint_from_request(
            method,
            &url,
            body,
            extract_headers(&config),
            target_base_url,
            DiscoverySource::FrontendRepo,
        );
    }

    None
}

fn parse_request_options(
    node: Node<'_>,
    source: &str,
    variables: &HashMap<String, String>,
) -> Option<HashMap<String, String>> {
    if node.kind() != "object" {
        return None;
    }

    let mut values = HashMap::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "pair" {
            continue;
        }
        let key = child
            .child_by_field_name("key")
            .map(|node| node_text(node, source))
            .or_else(|| child.named_child(0).map(|node| node_text(node, source)))?;
        let value_node = child
            .child_by_field_name("value")
            .or_else(|| child.named_child(1))?;

        let normalized_key = strip_quotes(&key).to_ascii_lowercase();
        if normalized_key == "headers" {
            for (header_name, header_value) in parse_headers_object(value_node, source, variables) {
                values.insert(format!("header:{header_name}"), header_value);
            }
            continue;
        }

        if normalized_key == "body" || normalized_key == "data" {
            if let Some(body) = resolve_request_body(value_node, source, variables) {
                values.insert("body".to_string(), body);
            }
            continue;
        }

        if let Some(value) = resolve_string_expression(value_node, source, variables) {
            values.insert(normalized_key, value);
        }
    }

    Some(values)
}

fn parse_headers_object(
    node: Node<'_>,
    source: &str,
    variables: &HashMap<String, String>,
) -> Vec<(String, String)> {
    if node.kind() != "object" {
        return Vec::new();
    }

    let mut headers = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "pair" {
            continue;
        }
        let Some(key_node) = child
            .child_by_field_name("key")
            .or_else(|| child.named_child(0))
        else {
            continue;
        };
        let Some(value_node) = child
            .child_by_field_name("value")
            .or_else(|| child.named_child(1))
        else {
            continue;
        };
        let key = strip_quotes(&node_text(key_node, source)).to_string();
        if let Some(value) = resolve_string_expression(value_node, source, variables) {
            headers.push((key, value));
        }
    }
    headers
}

fn extract_headers(options: &HashMap<String, String>) -> Vec<(String, String)> {
    options
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("header:")
                .map(|header_name| (header_name.to_string(), value.clone()))
        })
        .collect()
}

fn resolve_request_body(
    node: Node<'_>,
    source: &str,
    variables: &HashMap<String, String>,
) -> Option<String> {
    if let Some(value) = resolve_string_expression(node, source, variables) {
        return Some(value);
    }

    if node.kind() == "call_expression" {
        let function = node.child_by_field_name("function")?;
        let callee = node_text(function, source);
        if callee == "JSON.stringify" {
            return Some("{\"sample\":\"value\"}".to_string());
        }
    }

    if node.kind() == "object" {
        return Some("{\"sample\":\"value\"}".to_string());
    }

    None
}

fn resolve_string_expression(
    node: Node<'_>,
    source: &str,
    variables: &HashMap<String, String>,
) -> Option<String> {
    match node.kind() {
        "string" => Some(strip_quotes(&node_text(node, source)).to_string()),
        "template_string" => Some(normalize_template_string(
            &node_text(node, source),
            variables,
        )),
        "identifier" => variables.get(&node_text(node, source)).cloned(),
        "member_expression" => variables.get(&node_text(node, source)).cloned(),
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            let callee = node_text(function, source);
            let arguments = node.child_by_field_name("arguments")?;
            if named_children(arguments).is_empty() {
                return variables.get(&callee).cloned();
            }
            None
        }
        "parenthesized_expression" => node
            .named_child(0)
            .and_then(|child| resolve_string_expression(child, source, variables)),
        "binary_expression" => {
            let left = node
                .child_by_field_name("left")
                .and_then(|child| resolve_string_expression(child, source, variables));
            let right = node
                .child_by_field_name("right")
                .and_then(|child| resolve_string_expression(child, source, variables));
            match (left, right) {
                (Some(left), Some(right)) => Some(format!("{left}{right}")),
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                _ => None,
            }
        }
        "ternary_expression" => node
            .child_by_field_name("consequence")
            .and_then(|child| resolve_string_expression(child, source, variables))
            .or_else(|| {
                node.child_by_field_name("alternative")
                    .and_then(|child| resolve_string_expression(child, source, variables))
            }),
        "logical_expression" => node
            .child_by_field_name("right")
            .and_then(|child| resolve_string_expression(child, source, variables))
            .or_else(|| {
                node.child_by_field_name("left")
                    .and_then(|child| resolve_string_expression(child, source, variables))
            }),
        _ => None,
    }
}

fn build_endpoint_from_request(
    method: &str,
    raw_url: &str,
    body: Option<String>,
    headers: Vec<(String, String)>,
    target_base_url: &str,
    discovery_source: DiscoverySource,
) -> Option<SurfaceEndpoint> {
    let method = method.to_ascii_uppercase();
    let (path_template, query) = if raw_url.contains("{param}") {
        recover_api_path(raw_url)
            .or_else(|| normalize_relative_or_absolute_path(raw_url, target_base_url))
            .or_else(|| Some((raw_url.to_string(), None)))?
    } else {
        normalize_relative_or_absolute_path(raw_url, target_base_url)
            .or_else(|| recover_api_path(raw_url))
            .or_else(|| Some((raw_url.to_string(), None)))?
    };
    if !path_template.starts_with('/') {
        return None;
    }

    let execution_path = materialize_path_template(&path_template);
    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.clone());
    let auth_sensitive_headers = headers.iter().any(|(name, _)| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "authorization" | "cookie" | "x-api-key"
        )
    });
    let header_sensitive = headers.iter().any(|(name, _)| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "x-forwarded-for"
                | "x-forwarded-host"
                | "x-http-method-override"
                | "x-original-url"
                | "x-rewrite-url"
        )
    });
    let graphql = path_template.to_ascii_lowercase().contains("graphql")
        || content_type
            .as_ref()
            .map(|value| value.to_ascii_lowercase().contains("graphql"))
            .unwrap_or(false)
        || body
            .as_ref()
            .map(|value| {
                let lower = value.to_ascii_lowercase();
                lower.contains("query") || lower.contains("mutation")
            })
            .unwrap_or(false);

    let mut parser_traits = ParserTraits {
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
        graphql,
        query: query.is_some(),
        header_sensitive,
        same_origin_api: raw_url.starts_with("/api/") || path_template.starts_with("/api/"),
        dynamic_segments: path_template.contains('{') || path_template.contains(':'),
    };
    if method == "GET" && query.is_some() {
        parser_traits.query = true;
    }

    let mut content_types = Vec::new();
    if let Some(content_type) = &content_type {
        content_types.push(content_type.clone());
    } else if graphql || parser_traits.json {
        content_types.push("application/json".to_string());
    }

    let auth_class = if auth_sensitive_headers {
        AuthClass::Required
    } else {
        AuthClass::Unknown
    };
    let mut tags = Vec::new();
    if graphql {
        tags.push("graphql".to_string());
    }
    if path_template.to_ascii_lowercase().contains("tokenize") {
        tags.push("tokenization".to_string());
    }
    let mut confidence: f64 = if parser_traits.same_origin_api {
        0.72
    } else {
        0.62
    };
    if parser_traits.dynamic_segments {
        confidence -= 0.08;
    }

    let priority = infer_priority(
        &path_template,
        std::slice::from_ref(&method),
        &tags,
        auth_class,
    );
    Some(SurfaceEndpoint {
        endpoint_id: String::new(),
        path_template: path_template.clone(),
        execution_path: execution_path.clone(),
        methods: vec![method.clone()],
        content_types,
        auth_class,
        parser_traits,
        confidence: confidence.max(0.25),
        priority,
        tags,
        discovery_sources: vec![discovery_source],
        sample_request: Some(SampleRequest {
            method,
            path: execution_path,
            query,
            content_type,
            body,
        }),
        live_verification: None,
        excluded: false,
    })
}

fn endpoint_from_graphql_template(node: Node<'_>, source: &str) -> Option<SurfaceEndpoint> {
    let mut parts = named_children(node).into_iter();
    let tag = node.child_by_field_name("tag").or_else(|| parts.next())?;
    let tag_name = node_text(tag, source).to_ascii_lowercase();
    if tag_name != "gql" && tag_name != "graphql" {
        return None;
    }
    let template = node
        .child_by_field_name("template")
        .or_else(|| parts.next())?;
    let query = normalize_template_string(&node_text(template, source), &HashMap::new());
    let mut tags = vec!["graphql".to_string()];
    if query.to_ascii_lowercase().contains("mutation") {
        tags.push("mutation".to_string());
    }
    Some(SurfaceEndpoint {
        endpoint_id: String::new(),
        path_template: "/graphql".to_string(),
        execution_path: "/graphql".to_string(),
        methods: vec!["POST".to_string()],
        content_types: vec!["application/json".to_string()],
        auth_class: AuthClass::Unknown,
        parser_traits: ParserTraits {
            json: true,
            graphql: true,
            ..ParserTraits::default()
        },
        confidence: 0.45,
        priority: RoutePriority::High,
        tags,
        discovery_sources: vec![DiscoverySource::FrontendRepo],
        sample_request: Some(SampleRequest {
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            query: None,
            content_type: Some("application/json".to_string()),
            body: Some(format!(
                "{{\"query\":{}}}",
                serde_json::to_string(&query).ok()?
            )),
        }),
        live_verification: None,
        excluded: false,
    })
}

fn graphql_endpoint_from_source(source: &str) -> Option<SurfaceEndpoint> {
    if !(source.contains("gql`") || source.contains("graphql`")) {
        return None;
    }

    Some(SurfaceEndpoint {
        endpoint_id: String::new(),
        path_template: "/graphql".to_string(),
        execution_path: "/graphql".to_string(),
        methods: vec!["POST".to_string()],
        content_types: vec!["application/json".to_string()],
        auth_class: AuthClass::Unknown,
        parser_traits: ParserTraits {
            json: true,
            graphql: true,
            ..ParserTraits::default()
        },
        confidence: 0.4,
        priority: RoutePriority::High,
        tags: vec!["graphql".to_string()],
        discovery_sources: vec![DiscoverySource::FrontendRepo],
        sample_request: Some(SampleRequest {
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            query: None,
            content_type: Some("application/json".to_string()),
            body: Some("{\"query\":\"query { __typename }\"}".to_string()),
        }),
        live_verification: None,
        excluded: false,
    })
}

fn extract_same_origin_handler(
    file: &Path,
    repo_root: &Path,
    source: &str,
) -> Option<SurfaceEndpoint> {
    let relative = file.strip_prefix(repo_root).ok()?;
    let route = route_template_from_file(relative)?;
    let methods = handler_methods(source, file)?;
    let auth_class = if route.contains("/admin/") {
        AuthClass::Required
    } else {
        AuthClass::Unknown
    };

    Some(SurfaceEndpoint {
        endpoint_id: String::new(),
        path_template: route.clone(),
        execution_path: materialize_path_template(&route),
        methods: if methods.is_empty() {
            vec!["GET".to_string(), "POST".to_string()]
        } else {
            methods
        },
        content_types: Vec::new(),
        auth_class,
        parser_traits: ParserTraits {
            same_origin_api: route.starts_with("/api/"),
            dynamic_segments: route.contains('{'),
            ..ParserTraits::default()
        },
        confidence: 0.58,
        priority: infer_priority(&route, &[], &[], auth_class),
        tags: vec!["same_origin_handler".to_string()],
        discovery_sources: vec![DiscoverySource::FrontendRepo],
        sample_request: Some(SampleRequest {
            method: "GET".to_string(),
            path: materialize_path_template(&route),
            query: None,
            content_type: None,
            body: None,
        }),
        live_verification: None,
        excluded: false,
    })
}

fn route_template_from_file(relative: &Path) -> Option<String> {
    let path = relative.to_string_lossy().replace('\\', "/");
    if let Some(index) = path.find("/app/api/") {
        let suffix = &path[index + "/app".len()..];
        let trimmed = suffix
            .trim_end_matches("/route.ts")
            .trim_end_matches("/route.tsx")
            .trim_end_matches("/route.js")
            .trim_end_matches("/route.jsx");
        return Some(normalize_file_route(trimmed));
    }
    if path.starts_with("app/api/") {
        let trimmed = path
            .trim_start_matches("app")
            .trim_end_matches("/route.ts")
            .trim_end_matches("/route.tsx")
            .trim_end_matches("/route.js")
            .trim_end_matches("/route.jsx");
        return Some(normalize_file_route(trimmed));
    }
    if let Some(index) = path.find("/pages/api/") {
        let suffix = &path[index + "/pages".len()..];
        let trimmed = suffix
            .trim_end_matches(".ts")
            .trim_end_matches(".tsx")
            .trim_end_matches(".js")
            .trim_end_matches(".jsx");
        return Some(normalize_file_route(trimmed));
    }
    if path.starts_with("pages/api/") {
        let trimmed = format!(
            "/{}",
            path.trim_end_matches(".ts")
                .trim_end_matches(".tsx")
                .trim_end_matches(".js")
                .trim_end_matches(".jsx")
        );
        return Some(normalize_file_route(&trimmed));
    }
    None
}

fn normalize_file_route(route: &str) -> String {
    route
        .split('/')
        .map(|segment| {
            if segment.starts_with('[') && segment.ends_with(']') {
                let inner = segment
                    .trim_matches(&['[', ']'][..])
                    .trim_start_matches("...");
                format!("{{{inner}}}")
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn handler_methods(source: &str, file: &Path) -> Option<Vec<String>> {
    let language = language_for_path(file)?;
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(source, None)?;
    let mut methods = Vec::new();
    collect_handler_methods(tree.root_node(), source, &mut methods);
    methods.sort();
    methods.dedup();
    Some(methods)
}

fn collect_handler_methods(node: Node<'_>, source: &str, methods: &mut Vec<String>) {
    if node.kind() == "function_declaration" {
        if let Some(name) = node.child_by_field_name("name") {
            let candidate = node_text(name, source).to_ascii_uppercase();
            if matches!(
                candidate.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            ) {
                methods.push(candidate);
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_handler_methods(child, source, methods);
    }
}

fn axios_method_from_callee(callee: &str) -> Option<&'static str> {
    match callee {
        "axios.get" => Some("GET"),
        "axios.post" => Some("POST"),
        "axios.put" => Some("PUT"),
        "axios.patch" => Some("PATCH"),
        "axios.delete" => Some("DELETE"),
        "axios.head" => Some("HEAD"),
        "axios.options" => Some("OPTIONS"),
        _ => None,
    }
}

fn recover_api_path(raw_url: &str) -> Option<(String, Option<String>)> {
    static PATH_PATTERN: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r#"(/(?:api/|graphql(?:/|$)|v\d+/)[^?"'`\s]*)"#).unwrap()
    });

    let candidate = PATH_PATTERN
        .captures(raw_url)
        .and_then(|captures| captures.get(1).map(|matched| matched.as_str()))
        .or_else(|| {
            raw_url
                .find("/api/")
                .or_else(|| raw_url.find("/graphql"))
                .map(|index| &raw_url[index..])
        })?;
    let (path, query) = candidate
        .split_once('?')
        .map(|(path, query)| (path.to_string(), Some(query.to_string())))
        .unwrap_or_else(|| (candidate.to_string(), None));
    Some((path, query))
}

fn normalize_template_string(value: &str, variables: &HashMap<String, String>) -> String {
    static CALL_TEMPLATE: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r"\$\{\s*([A-Za-z_][A-Za-z0-9_.]*)\(\s*\)\s*\}").unwrap()
    });
    static IDENT_TEMPLATE: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r"\$\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}").unwrap()
    });
    static ANY_TEMPLATE: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| Regex::new(r"\$\{[^}]+\}").unwrap());

    let trimmed = value.trim_matches('`');
    let substituted_calls = CALL_TEMPLATE.replace_all(trimmed, |captures: &regex::Captures<'_>| {
        variables
            .get(&captures[1])
            .cloned()
            .unwrap_or_else(|| "{param}".to_string())
    });
    let substituted = IDENT_TEMPLATE.replace_all(
        substituted_calls.as_ref(),
        |captures: &regex::Captures<'_>| {
            variables
                .get(&captures[1])
                .cloned()
                .unwrap_or_else(|| "{param}".to_string())
        },
    );

    ANY_TEMPLATE
        .replace_all(substituted.as_ref(), "{param}")
        .to_string()
}

fn strip_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value)
}

fn node_text(node: Node<'_>, source: &str) -> String {
    node.utf8_text(source.as_bytes())
        .unwrap_or_default()
        .to_string()
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor: TreeCursor<'_> = node.walk();
    node.named_children(&mut cursor).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_extract_frontend_endpoints_finds_fetch_axios_and_graphql() {
        let tempdir = TempDir::new().expect("tempdir");
        fs::create_dir_all(tempdir.path().join("src")).unwrap();
        fs::write(
            tempdir.path().join("src/api.ts"),
            r#"
            const API_BASE = "https://api.example.com/v1";
            export async function load() {
              await fetch(`${API_BASE}/tokenize`, {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  Authorization: process.env.TOKEN || "Bearer test"
                },
                body: JSON.stringify({ value: "secret" })
              });
              await axios.get("/api/search?q=test");
              const query = gql`mutation Tokenize($value: String!) { tokenize(value: $value) }`;
            }
        "#,
        )
        .unwrap();

        let endpoints =
            extract_frontend_endpoints(tempdir.path(), "https://app.example.com").unwrap();
        assert!(endpoints
            .iter()
            .any(|endpoint| endpoint.path_template == "/v1/tokenize"));
        assert!(endpoints
            .iter()
            .any(|endpoint| endpoint.path_template == "/api/search"));
        assert!(endpoints
            .iter()
            .any(|endpoint| endpoint.path_template == "/graphql"));
    }

    #[test]
    fn test_extract_frontend_endpoints_resolves_helper_and_object_endpoints() {
        let tempdir = TempDir::new().expect("tempdir");
        fs::create_dir_all(tempdir.path().join("src")).unwrap();
        fs::write(
            tempdir.path().join("src/pts.ts"),
            r#"
            const Endpoints = {
              APPLE_SESSION: `${getDomain()}/v1/applePay/session`,
              PAYMENT_TOKENS: `${getDomain()}/v5/payment_tokens`
            };

            function getDomain() {
              return "https://payments.example.com";
            }

            function getPTSEndpoint() {
              return `${getDomain()}/v4/payment_tokens`;
            }

            export async function submit(fetcher) {
              await fetch(`${getPTSEndpoint()}?api_key=test`, {
                method: "POST",
                body: JSON.stringify({ value: "secret" })
              });
              await fetch(Endpoints.APPLE_SESSION, { method: "POST" });
              await fetch(Endpoints.PAYMENT_TOKENS, { method: "POST" });
            }
        "#,
        )
        .unwrap();

        let endpoints =
            extract_frontend_endpoints(tempdir.path(), "https://app.example.com").unwrap();
        assert!(endpoints
            .iter()
            .any(|endpoint| endpoint.path_template == "/v4/payment_tokens"));
        assert!(endpoints
            .iter()
            .any(|endpoint| endpoint.path_template == "/v1/applePay/session"));
        assert!(endpoints
            .iter()
            .any(|endpoint| endpoint.path_template == "/v5/payment_tokens"));
    }

    #[test]
    fn test_extract_same_origin_handler_route() {
        let tempdir = TempDir::new().expect("tempdir");
        let route_dir = tempdir.path().join("app/api/tokenize");
        fs::create_dir_all(&route_dir).unwrap();
        let route_path = route_dir.join("route.ts");
        fs::write(
            &route_path,
            "export async function POST() { return Response.json({ ok: true }); }",
        )
        .unwrap();

        let endpoint = extract_same_origin_handler(
            &route_path,
            tempdir.path(),
            &fs::read_to_string(&route_path).unwrap(),
        )
        .unwrap();
        assert_eq!(endpoint.path_template, "/api/tokenize");
        assert!(endpoint.methods.contains(&"POST".to_string()));
    }
}
