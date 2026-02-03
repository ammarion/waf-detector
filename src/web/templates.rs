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
            <h3><span class="method post">POST</span> /api/virtual-adversary</h3>
            <p>Run Virtual Adversary effectiveness testing (consent required).</p>

            <h4>Request Body</h4>
            <pre><code>{
  "url": "https://example.com",
  "tier": 2,
  "budget": 120,
  "timeout_ms": 15000,
  "delay_ms": 750,
  "variants": 4
}</code></pre>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "result": {
    "target_url": "https://example.com",
    "plan_size": 24,
    "summary": {
      "total": 24,
      "blocked": 14,
      "challenge": 4,
      "allowed": 6,
      "error": 0
    },
    "config": {
      "tier": 2,
      "request_budget": 120,
      "request_timeout": { "secs": 15, "nanos": 0 },
      "request_delay": { "secs": 0, "nanos": 750000000 },
      "max_variants_per_payload": 4
    },
    "results": [
      {
        "payload": "' OR '1'='1",
        "category": "SqlInjection",
        "outcome": "Blocked",
        "reason": "status=403"
      }
    ]
  },
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/virtual-adversary/start</h3>
            <p>Start a Virtual Adversary run asynchronously and return a job id.</p>

            <h4>Request Body</h4>
            <pre><code>{
  "url": "https://example.com",
  "tier": 2,
  "budget": 120,
  "timeout_ms": 15000,
  "delay_ms": 750,
  "variants": 4
}</code></pre>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "job_id": "va-42",
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/virtual-adversary/status/:id</h3>
            <p>Check progress for a running Virtual Adversary job.</p>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "status": {
    "id": "va-42",
    "state": "running",
    "total": 24,
    "completed": 6,
    "result": null,
    "error": null,
    "events": [
      {
        "index": 6,
        "total": 24,
        "category": "SqlInjection",
        "payload": "' OR '1'='1",
        "outcome": "Blocked",
        "reason": "status=403",
        "timestamp": "2026-02-03T12:00:00Z"
      }
    ]
  },
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/virtual-adversary/reports</h3>
            <p>List saved Virtual Adversary reports.</p>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "reports": [
    {
      "id": "va-20260203T120000-example.com.json",
      "target_url": "https://example.com",
      "created_at": "2026-02-03T12:00:00Z",
      "plan_size": 24,
      "blocked": 10,
      "challenge": 4,
      "allowed": 8,
      "error": 2,
      "risk_label": "MEDIUM"
    }
  ],
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/virtual-adversary/reports.csv</h3>
            <p>Download saved Virtual Adversary reports as CSV.</p>

            <h4>Response</h4>
            <pre><code>id,target_url,created_at,plan_size,blocked,challenge,allowed,error,risk_label
va-20260203T120000-example.com.json,https://example.com,2026-02-03T12:00:00Z,24,10,4,8,2,MEDIUM</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/virtual-adversary/reports/cleanup</h3>
            <p>Apply retention to saved Virtual Adversary reports.</p>

            <h4>Request Body</h4>
            <pre><code>{
  "max_reports": 50
}</code></pre>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "kept": 50,
  "deleted": 12,
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/virtual-adversary/reports/delete-range</h3>
            <p>Delete saved Virtual Adversary reports in a date range (inclusive).</p>

            <h4>Request Body</h4>
            <pre><code>{
  "start_date": "2026-02-01",
  "end_date": "2026-02-02"
}</code></pre>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "deleted": 8,
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/virtual-adversary/reports/:id</h3>
            <p>Fetch a saved Virtual Adversary report by id.</p>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "report": {
    "id": "va-20260203T120000-example.com.json",
    "created_at": "2026-02-03T12:00:00Z",
    "report": {
      "target_url": "https://example.com",
      "plan_size": 24,
      "replay_plan": [
        {
          "index": 1,
          "class": "SemanticDrift",
          "channel": "Query",
          "description": "Duplicate key ordering drift",
          "method": "GET",
          "url": "https://example.com/?a=1&a=2",
          "headers": [],
          "body": null
        }
      ],
      "summary": {
        "total": 24,
        "blocked": 10,
        "challenge": 4,
        "allowed": 8,
        "error": 2
      },
      "config": {
        "tier": 2,
        "request_budget": 120,
        "request_timeout": { "secs": 15, "nanos": 0 },
        "request_delay": { "secs": 0, "nanos": 750000000 },
        "max_variants_per_payload": 4
      },
      "results": []
    }
  },
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/virtual-adversary/reports/:id/csv</h3>
            <p>Download a saved Virtual Adversary report as CSV.</p>

            <h4>Response</h4>
            <pre><code>report_id,target_url,created_at,index,category,payload,outcome,reason,evidence,probe_class,probe_channel,probe_description,method,url
va-20260203T120000-example.com.json,https://example.com,2026-02-03T12:00:00Z,1,SqlInjection,' OR '1'='1,Blocked,status=403,,SemanticDrift,Query,Duplicate key ordering drift,GET,https://example.com/?a=1&a=2</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/virtual-adversary/reports/:id/replay.json</h3>
            <p>Download the replay plan JSON for a saved Virtual Adversary report.</p>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "replay_plan": [
    {
      "index": 1,
      "class": "SemanticDrift",
      "channel": "Query",
      "description": "Duplicate key ordering drift",
      "method": "GET",
      "url": "https://example.com/?a=1&a=2",
      "headers": [],
      "body": null
    }
  ],
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/virtual-adversary/reports/:id/replay.csv</h3>
            <p>Download the replay plan CSV for a saved Virtual Adversary report.</p>

            <h4>Response</h4>
            <pre><code>index,probe_class,probe_channel,probe_description,method,url,headers,body
1,SemanticDrift,Query,Duplicate key ordering drift,GET,https://example.com/?a=1&a=2,[],</code></pre>
        </div>


        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/consent-status</h3>
            <p>Return consent status and authorized targets for the local user.</p>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "status": {
    "has_consent": true,
    "terms_version": "1.0.0",
    "expires_in_days": 23,
    "authorized_targets": ["example.com"],
    "consent_timestamp": "2026-02-03T10:00:00Z"
  },
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/consent/add-target</h3>
            <p>Add an authorized target to the consent list.</p>

            <h4>Request Body</h4>
            <pre><code>{
  "target": "example.com"
}</code></pre>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "status": {
    "has_consent": true,
    "terms_version": "1.0.0",
    "expires_in_days": 23,
    "authorized_targets": ["example.com"],
    "consent_timestamp": "2026-02-03T10:00:00Z"
  },
  "error": null
}</code></pre>
        </div>

        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/consent/remove-target</h3>
            <p>Remove an authorized target from the consent list.</p>

            <h4>Request Body</h4>
            <pre><code>{
  "target": "example.com"
}</code></pre>

            <h4>Response</h4>
            <pre><code>{
  "success": true,
  "status": {
    "has_consent": true,
    "terms_version": "1.0.0",
    "expires_in_days": 23,
    "authorized_targets": [],
    "consent_timestamp": "2026-02-03T10:00:00Z"
  },
  "error": null
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
        assert!(DASHBOARD_HTML.contains("vaTestForm"));
        assert!(DASHBOARD_HTML.contains("Download VA Report"));
        assert!(DASHBOARD_HTML.contains("consentTargetInput"));
        assert!(DASHBOARD_HTML.contains("vaHistoryList"));
        assert!(DASHBOARD_HTML.contains("vaActivityLog"));
        assert!(DASHBOARD_HTML.contains("reports.csv"));
        assert!(DASHBOARD_HTML.contains("vaRetentionInput"));
        assert!(DASHBOARD_HTML.contains("vaActivityFilter"));
        assert!(DASHBOARD_HTML.contains("downloadVaReportCsv"));
        assert!(DASHBOARD_HTML.contains("vaHistorySearch"));
        assert!(DASHBOARD_HTML.contains("vaAutoScroll"));
        assert!(DASHBOARD_HTML.contains("vaHistoryDate"));
        assert!(DASHBOARD_HTML.contains("vaReportModal"));
        assert!(DASHBOARD_HTML.contains("vaHistorySort"));
        assert!(DASHBOARD_HTML.contains("vaActivitySearch"));
        assert!(DASHBOARD_HTML.contains("deleteVaHistoryRange"));
        assert!(DASHBOARD_HTML.contains("Replay Plan"));
        assert!(DASHBOARD_HTML.contains("vaReplayPlanPanel"));
        assert!(DASHBOARD_HTML.contains("vaReplaySearch"));
        assert!(DASHBOARD_HTML.contains("vaReplayClassFilter"));
        assert!(DASHBOARD_HTML.contains("vaReplayChannelFilter"));
        assert!(DASHBOARD_HTML.contains("vaReplayMethodFilter"));
    }
}
