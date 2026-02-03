pub const DASHBOARD_HTML: &str = include_str!("templates/dashboard.html");

pub const API_DOCS_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Detector API Documentation</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 2rem;
            background: #f8fafc;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1, h2, h3 {
            color: #2d3748;
        }
        
        .endpoint {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }
        
        .method {
            background: #667eea;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: bold;
            display: inline-block;
            margin-right: 0.5rem;
        }
        
        .method.post {
            background: #48bb78;
        }
        
        .method.get {
            background: #4299e1;
        }
        
        code {
            background: #f5f5f5;
            color: #222;
            padding: 0.125rem 0.25rem;
            border-radius: 4px;
            font-family: 'Monaco', 'Consolas', monospace;
        }
        
        pre {
            background: #f5f5f5;
            color: #222;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
        }
        
        .back-link {
            display: inline-block;
            margin-bottom: 2rem;
            color: #667eea;
            text-decoration: none;
        }
        
        .back-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">← Back to Dashboard</a>
        
        <h1>🔗 WAF Detector API Documentation</h1>
        
        <h2>Authentication</h2>
        <p>No authentication required for local usage.</p>
        
        <h2>Endpoints</h2>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/scan</h3>
            <p>Scan a single URL for WAF/CDN detection.</p>
            
            <h4>Request Body</h4>
            <pre><code>{
  "url": "https://example.com",
  "debug": true
}</code></pre>
            
            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "result": {
    "url": "https://example.com",
    "detected_waf": {
      "name": "CloudFlare",
      "confidence": 0.85
    },
    "detected_cdn": {
      "name": "CloudFlare", 
      "confidence": 0.85
    },
    "evidence": [...],
    "detection_time_ms": 150,
    "timestamp": "2024-01-01T12:00:00Z"
  },
  "error": null
}</code></pre>
        </div>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/batch-scan</h3>
            <p>Scan multiple URLs in batch.</p>
            
            <h4>Request Body</h4>
            <pre><code>{
  "urls": [
    "https://example1.com",
    "https://example2.com"
  ],
  "debug": true
}</code></pre>
            
            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "results": [
    { /* DetectionResult object */ },
    { /* DetectionResult object */ }
  ],
  "error": null
}</code></pre>
        </div>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/smoke-test</h3>
            <p>Run detailed WAF smoke test with individual payload results.</p>
            
            <h4>Request Body</h4>
            <pre><code>{
  "url": "https://example.com"
}</code></pre>
            
            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "result": {
    "url": "https://example.com",
    "effectiveness_percentage": 85.7,
    "waf_mode": "Blocking",
    "identified_waf": "CloudFlare",
    "total_time_ms": 1250,
    "test_results": [
      {
        "category": "SQL Injection",
        "payload": "' OR '1'='1",
        "status": "BLOCKED",
        "status_code": 403,
        "response_time_ms": 95
      }
    ]
  }
}</code></pre>
        </div>
        
        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/providers</h3>
            <p>List all available detection providers.</p>
            
            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "providers": [
    {
      "name": "CloudFlare",
      "version": "1.0.0",
      "type": "Both",
      "description": "CloudFlare WAF and CDN detection"
    }
  ]
}</code></pre>
        </div>
        
        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/status</h3>
            <p>Get server health status.</p>
            
            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-01T12:00:00Z"
}</code></pre>
        </div>
        
        <h2>Error Handling</h2>
        <p>All endpoints return consistent error responses:</p>
        <pre><code>{
  "success": false,
  "error": "Error description here"
}</code></pre>
        
        <h2>Rate Limiting</h2>
        <p>No rate limiting implemented for local usage.</p>
        
        <h2>CORS</h2>
        <p>CORS is enabled for all origins in development mode.</p>
    </div>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::DASHBOARD_HTML;

    #[test]
    fn dashboard_html_contains_va_placeholder() {
        assert!(DASHBOARD_HTML.contains("Virtual Adversary"));
    }
}
