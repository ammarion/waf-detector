//! Shared test utilities for provider unit tests.

use crate::http::HttpResponse;
use std::collections::HashMap;

/// Build a mock HTTP response for provider testing.
pub fn mock_response(
    status: u16,
    headers: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    body: impl Into<String>,
) -> HttpResponse {
    let headers: HashMap<String, String> = headers
        .into_iter()
        .map(|(k, v)| (k.as_ref().to_lowercase(), v.as_ref().to_string()))
        .collect();
    HttpResponse {
        status,
        headers,
        body: body.into(),
        url: "https://example.com/".to_string(),
    }
}
