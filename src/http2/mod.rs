//! HTTP/2 SETTINGS Frame Fingerprinting for WAF/CDN Detection
//!
//! This module captures and analyzes HTTP/2 SETTINGS frames to identify
//! WAF/CDN providers. Each provider has distinct HTTP/2 configurations that
//! provide a reliable fingerprint.

pub mod fingerprint;

pub use fingerprint::{H2FingerprintAnalyzer, H2Settings};
