pub const DASHBOARD_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Detector Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            text-align: center;
            margin-bottom: 3rem;
            color: white;
        }

        .header h1 {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }

        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 3rem;
        }

        .card {
            background: white;
            border-radius: 16px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }

        .card h2 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: #2d3748;
        }

        .input-group {
            margin-bottom: 1.5rem;
        }

        .input-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #4a5568;
        }

        .input-field {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }

        .input-field:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 0.75rem 2rem;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .btn-secondary {
            background: #4a5568;
        }

        .btn-secondary:hover {
            box-shadow: 0 5px 15px rgba(74, 85, 104, 0.4);
        }

        .results-section {
            background: white;
            border-radius: 16px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-top: 2rem;
        }

        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .results-header h2 {
            color: #2d3748;
        }

        .result-card {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            transition: all 0.3s ease;
        }

        .result-card:hover {
            background: #edf2f7;
            border-color: #cbd5e0;
        }

        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }

        .result-url {
            font-weight: 600;
            color: #2d3748;
            font-size: 1.1rem;
        }

        .result-time {
            font-size: 0.875rem;
            color: #718096;
        }

        .detection-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .detection-item {
            padding: 1rem;
            border-radius: 8px;
            background: white;
            border: 2px solid #e2e8f0;
        }

        .detection-item.detected {
            border-color: #48bb78;
            background: #f0fff4;
        }

        .detection-item.not-detected {
            border-color: #f56565;
            background: #fffafa;
        }

        .detection-label {
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }

        .detection-value {
            font-size: 1.125rem;
            font-weight: 700;
        }

        .confidence-bar {
            background: #e2e8f0;
            height: 6px;
            border-radius: 3px;
            margin-top: 0.5rem;
            overflow: hidden;
        }

        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #48bb78 0%, #38a169 100%);
            transition: width 0.5s ease;
        }

        .evidence-section {
            margin-top: 1rem;
        }

        .evidence-toggle {
            background: none;
            border: none;
            color: #667eea;
            font-weight: 600;
            cursor: pointer;
            text-decoration: underline;
        }

        .evidence-list {
            margin-top: 1rem;
            padding-left: 1rem;
            border-left: 3px solid #667eea;
            background: #f8faff;
            padding: 1rem;
            border-radius: 8px;
            display: none;
        }
        
        .evidence-list table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            font-size: 0.9rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        }
        
        .evidence-list th {
            background-color: #f1f5f9;
            padding: 0.75rem;
            text-align: left;
            border-bottom: 2px solid #e2e8f0;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        .evidence-list td {
            padding: 0.75rem;
            vertical-align: middle;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .evidence-list tr:nth-child(even) {
            background-color: #f8fafc;
        }
        
        .evidence-list tr:hover {
            background-color: #f0f9ff;
        }
        
        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }
        
        .status-blocked {
            background-color: #22c55e;
        }
        
        .status-allowed {
            background-color: #ef4444;
        }
        
        .status-challenge {
            background-color: #0ea5e9;
        }
        
        .summary-table {
            margin-top: 1.5rem;
            background-color: #f0f9ff;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #0ea5e9;
        }

        .evidence-item {
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
            padding: 0.5rem;
            border-radius: 6px;
            background: #fafbfc;
            border: 1px solid #e1e5e9;
        }

        .evidence-timing {
            background: #fff7ed !important;
            border: 1px solid #fed7aa !important;
            border-left: 4px solid #f97316 !important;
        }

        .evidence-dns {
            background: #f0fdf4 !important;
            border: 1px solid #bbf7d0 !important;
            border-left: 4px solid #22c55e !important;
        }

        .evidence-payload {
            background: #fdf2f8 !important;
            border: 1px solid #fbb6ce !important;
            border-left: 4px solid #ec4899 !important;
        }

        .confidence-badge {
            display: inline-block;
            padding: 0.125rem 0.375rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }

        .confidence-high {
            background: #dcfce7;
            color: #166534;
        }

        .confidence-medium {
            background: #fef3c7;
            color: #92400e;
        }

        .confidence-low {
            background: #fee2e2;
            color: #991b1b;
        }

        .timing-info {
            color: #ea580c;
            font-weight: 600;
            font-size: 0.75rem;
        }

        .dns-info {
            color: #16a34a;
            font-weight: 600;
            font-size: 0.75rem;
        }

        .payload-info {
            color: #be185d;
            font-weight: 600;
            font-size: 0.75rem;
        }

        .loading {
            text-align: center;
            padding: 2rem;
            color: #718096;
        }

        .spinner {
            display: inline-block;
            width: 24px;
            height: 24px;
            border: 3px solid #e2e8f0;
            border-radius: 50%;
            border-top-color: #667eea;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }

        .status-detected {
            background: #48bb78;
        }

        .status-not-detected {
            background: #f56565;
        }

        .batch-input {
            min-height: 120px;
            resize: vertical;
        }

        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .detection-info {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 1rem;
            }
            
            .header h1 {
                font-size: 2rem;
            }
        }

        .error-message {
            background: #fed7d7;
            color: #c53030;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            border: 1px solid #feb2b2;
        }

        .success-message {
            background: #c6f6d5;
            color: #2f855a;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            border: 1px solid #9ae6b4;
        }

        .payload-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            font-size: 0.875rem;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .payload-table th {
            background: #f8fafc;
            padding: 0.75rem 0.5rem;
            text-align: left;
            font-weight: 600;
            color: #374151;
            border-bottom: 1px solid #e5e7eb;
            white-space: nowrap;
        }

        .payload-table td {
            padding: 0.5rem;
            border-bottom: 1px solid #f3f4f6;
            vertical-align: top;
            max-width: 300px;
            word-wrap: break-word;
            word-break: break-all;
            overflow-wrap: break-word;
        }

        .payload-table td:nth-child(2) {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.75rem;
            max-width: 200px;
            white-space: pre-wrap;
        }

        .payload-table tr:hover {
            background: #f9fafb;
        }

        .payload-table tr:last-child td {
            border-bottom: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ WAF Detector</h1>
            <p>Advanced Security Infrastructure Analysis & Visualization</p>
            <p style="font-size: 0.8rem; color: #f8fafc; background-color: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 6px; margin-top: 0.5rem;">⚠️ <strong>Important:</strong> This tool should only be used against your own web services or with explicit authorization. Unauthorized scanning may violate terms of service or laws in your jurisdiction.</p>
        </div>

        <div class="dashboard-grid">
            <div class="card">
                <h2>🚀 Single URL Detection</h2>
                <form id="singleScanForm">
                    <div class="input-group">
                        <label for="singleUrl">Enter URL to scan:</label>
                        <input type="url" id="singleUrl" class="input-field" placeholder="https://example.com" required>
                    </div>
                    <button type="submit" class="btn">
                        <span id="singleScanIcon">🚀</span>
                        <span id="singleScanText">Scan URL</span>
                    </button>
                </form>
            </div>

            <div class="card">
                <h2>⚡ Batch URL Detection</h2>
                <form id="batchScanForm">
                    <div class="input-group">
                        <label for="batchUrls">Enter URLs (one per line):</label>
                        <textarea id="batchUrls" class="input-field" rows="4" placeholder="https://example1.com&#10;https://example2.com" required></textarea>
                    </div>
                    <button type="submit" class="btn">
                        <span id="batchScanIcon">⚡</span>
                        <span id="batchScanText">Scan Batch</span>
                    </button>
                </form>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="card">
                <h2>🛡️ WAF Smoke Test</h2>
                <p style="margin-bottom: 1rem; color: #666; font-size: 0.95rem;">
                    Live payload testing with detailed results - see every attack tested and blocked!
                </p>
                <form id="smokeTestForm">
                    <div class="input-group">
                        <label for="smokeTestUrl">Enter URL to test:</label>
                        <input type="url" id="smokeTestUrl" class="input-field" placeholder="https://example.com" required>
                    </div>
                    <button type="submit" class="btn">
                        <span id="smokeTestIcon">🛡️</span>
                        <span id="smokeTestText">Run Smoke Test</span>
                    </button>
                </form>
            </div>

            <div class="card">
                <h2>📊 Quick Actions</h2>
                <div style="display: flex; flex-direction: column; gap: 1rem;">
                    <button onclick="clearResults()" class="btn btn-secondary">
                        🗑️ Clear Results
                    </button>
                    <button onclick="window.open('/api-docs', '_blank')" class="btn btn-secondary">
                        📖 API Documentation
                    </button>
                    <button onclick="exportResults()" class="btn btn-secondary">
                        💾 Export Results
                    </button>
                </div>
            </div>
        </div>

        <!-- Results Section -->
        <div id="resultsSection" class="results-section" style="display: none;">
            <div class="results-header">
                <h2>📊 Detection Results</h2>
                <span id="resultsCount">0 results</span>
            </div>
            <div id="resultsContainer">
                <!-- Results will be populated here -->
            </div>
        </div>
    </div>

    <script>
        let allResults = [];

        // HTML escaping utility to prevent XSS
        function escapeHtml(str) {
            if (typeof str !== 'string') return str;
            return str.replace(/[&<>\"'`=\\/]/g, function(s) {
                return ({
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#39;',
                    '`': '&#96;',
                    '=': '&#61;',
                    '/': '&#47;'
                })[s];
            });
        }

        // Helper function to display status codes safely
        function displayStatusCode(val) {
            if (val === undefined || val === null || isNaN(val)) return 'N/A';
            return String(val);
        }

        // Single URL scan
        document.getElementById('singleScanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('singleUrl').value;
            await scanSingleUrl(url);
        });

        // Batch URL scan
        document.getElementById('batchScanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const urlsText = document.getElementById('batchUrls').value;
            const urls = urlsText.split('\n').filter(url => url.trim()).map(url => url.trim());
            await scanBatchUrls(urls);
        });

        // WAF Smoke Testing
        document.getElementById('smokeTestForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('smokeTestUrl').value;
            await runSmokeTest(url);
        });

        async function scanSingleUrl(url) {
            const btn = document.querySelector('#singleScanForm button');
            const icon = document.getElementById('singleScanIcon');
            const text = document.getElementById('singleScanText');
            
            setButtonLoading(btn, icon, text, true);
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, debug: true })
                });
                
                const data = await response.json();
                
                if (data.success && data.result) {
                    allResults.unshift(data.result);
                    displayResults();
                    showSuccessMessage(`Successfully scanned ${url}`);
                } else {
                    showErrorMessage(data.error || 'Scan failed');
                }
            } catch (error) {
                showErrorMessage(`Error: ${error.message}`);
            } finally {
                setButtonLoading(btn, icon, text, false);
            }
        }

        async function scanBatchUrls(urls) {
            const btn = document.querySelector('#batchScanForm button');
            const icon = document.getElementById('batchScanIcon');
            const text = document.getElementById('batchScanText');
            
            setButtonLoading(btn, icon, text, true);
            
            try {
                const response = await fetch('/api/batch-scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ urls, debug: true })
                });
                
                const data = await response.json();
                
                if (data.success && data.results) {
                    allResults.unshift(...data.results.reverse());
                    displayResults();
                    showSuccessMessage(`Successfully scanned ${urls.length} URLs`);
                } else {
                    showErrorMessage(data.error || 'Batch scan failed');
                }
            } catch (error) {
                showErrorMessage(`Error: ${error.message}`);
            } finally {
                setButtonLoading(btn, icon, text, false);
            }
        }

        async function runSmokeTest(url) {
            const btn = document.querySelector('#smokeTestForm button');
            const icon = document.getElementById('smokeTestIcon');
            const text = document.getElementById('smokeTestText');
            
            setButtonLoading(btn, icon, text, true, 'Testing...');
            
            try {
                const response = await fetch('/api/smoke-test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                
                const data = await response.json();
                
                if (data.success && data.result) {
                    // Mark this as a smoke test result explicitly
                    data.result.is_smoke_test = true;
                    allResults.unshift(data.result);
                    displayResults();
                    showSuccessMessage(`Smoke test completed for ${url} - ${data.result.test_results ? data.result.test_results.length : 0} payloads tested`);
                } else {
                    showErrorMessage(data.error || 'Smoke test failed');
                }
            } catch (error) {
                showErrorMessage(`Error: ${error.message}`);
            } finally {
                setButtonLoading(btn, icon, text, false, 'Run Smoke Test');
            }
        }

        function setButtonLoading(btn, icon, text, loading, customText = null) {
            if (loading) {
                btn.disabled = true;
                icon.innerHTML = '<div class="spinner"></div>';
                text.textContent = customText || 'Scanning...';
            } else {
                btn.disabled = false;
                const buttonId = btn.closest('form').id;
                if (buttonId === 'batchScanForm') {
                    icon.innerHTML = '⚡';
                    text.textContent = 'Scan Batch';
                } else if (buttonId === 'smokeTestForm') {
                    icon.innerHTML = '🛡️';
                    text.textContent = customText || 'Run Smoke Test';
                } else {
                    icon.innerHTML = '🚀';
                    text.textContent = 'Scan URL';
                }
            }
        }

        function displayResults() {
            const section = document.getElementById('resultsSection');
            const container = document.getElementById('resultsContainer');
            const count = document.getElementById('resultsCount');
            
            section.style.display = 'block';
            count.textContent = `${allResults.length} result${allResults.length !== 1 ? 's' : ''}`;
            
            container.innerHTML = allResults.map(result => createResultCard(result)).join('');
        }

        function createResultCard(result) {
            // Ensure result is defined
            if (!result) {
                console.error("Result is undefined");
                return '<div class="result-card">Error: Invalid result data</div>';
            }
            
            // Check if this is a smoke test result (has test_results property AND other smoke test indicators)
            const isSmokeTest = (result.test_results !== undefined && Array.isArray(result.test_results) && result.test_results.length > 0) || 
                               result.is_smoke_test === true ||
                               (result.summary && result.summary.effectiveness_percentage !== undefined);
            
            console.log("Creating result card for:", result);
            console.log("isSmokeTest:", isSmokeTest, "is_smoke_test flag:", result.is_smoke_test, "detected_waf:", result.detected_waf, "detected_cdn:", result.detected_cdn);
            console.log("test_results array:", Array.isArray(result.test_results), "length:", result.test_results ? result.test_results.length : 0);
            // Check if this is a combined result (has detection_result property)
            const isCombined = result.detection_result !== undefined;
            const detectionData = isCombined && result.detection_result ? result.detection_result : result;
            
            // Initialize variables safely
            let wafDetected = false;
            let cdnDetected = false;
            let wafName = 'Not Detected';
            let cdnName = 'Not Detected';
            let wafConfidence = 0;
            let cdnConfidence = 0;
            
            // For smoke test results, use the detected_waf property directly
            if (isSmokeTest) {
                // Handle detected_waf safely (can be null, string, or object)
                if (result.detected_waf && result.detected_waf !== null && result.detected_waf !== 'Unknown') {
                    wafDetected = true;
                    if (typeof result.detected_waf === 'string') {
                        wafName = result.detected_waf;
                    } else if (typeof result.detected_waf === 'object' && result.detected_waf.name) {
                        wafName = result.detected_waf.name;
                        wafConfidence = result.detected_waf.confidence ? (result.detected_waf.confidence * 100).toFixed(1) : 95;
                    } else {
                        wafName = 'Detected WAF';
                    }
                    if (!wafConfidence) wafConfidence = 95; // Default high confidence for smoke test detections
                }
                
                // Handle detected_cdn safely (can be null, string, or object)
                if (result.detected_cdn && result.detected_cdn !== null && result.detected_cdn !== 'Unknown') {
                    cdnDetected = true;
                    if (typeof result.detected_cdn === 'string') {
                        cdnName = result.detected_cdn;
                    } else if (typeof result.detected_cdn === 'object' && result.detected_cdn.name) {
                        cdnName = result.detected_cdn.name;
                        cdnConfidence = result.detected_cdn.confidence ? (result.detected_cdn.confidence * 100).toFixed(1) : 95;
                    } else {
                        cdnName = 'Detected CDN';
                    }
                    if (!cdnConfidence) cdnConfidence = 95; // Default high confidence
                }
            } 
            // For regular detection results or combined results
            else {
                // Safely check if detected_waf exists and is not null
                if (detectionData && detectionData.detected_waf && detectionData.detected_waf !== null) {
                    if (typeof detectionData.detected_waf === 'object' && detectionData.detected_waf.name) {
                        wafDetected = true;
                        wafName = detectionData.detected_waf.name;
                        wafConfidence = detectionData.detected_waf.confidence ? (detectionData.detected_waf.confidence * 100).toFixed(1) : 0;
                    } else if (typeof detectionData.detected_waf === 'string') {
                        wafDetected = true;
                        wafName = detectionData.detected_waf;
                        wafConfidence = 95; // Default confidence for string detection
                    }
                }
                
                // Safely check if detected_cdn exists and is not null
                if (detectionData && detectionData.detected_cdn && detectionData.detected_cdn !== null) {
                    if (typeof detectionData.detected_cdn === 'object' && detectionData.detected_cdn.name) {
                        cdnDetected = true;
                        cdnName = detectionData.detected_cdn.name;
                        cdnConfidence = detectionData.detected_cdn.confidence ? (detectionData.detected_cdn.confidence * 100).toFixed(1) : 0;
                    } else if (typeof detectionData.detected_cdn === 'string') {
                        cdnDetected = true;
                        cdnName = detectionData.detected_cdn;
                        cdnConfidence = 95; // Default confidence for string detection
                    }
                }
            }
            
            return `
                <div class="result-card">
                    <div class="result-header">
                        <div class="result-url">${escapeHtml(isSmokeTest && result.url ? result.url : 
                                               isCombined && result.url ? result.url : 
                                               detectionData && detectionData.url ? detectionData.url : 
                                               "Unknown URL")}</div>
                        <div class="result-time">${isSmokeTest && result.total_time_ms ? result.total_time_ms : 
                                                isCombined && result.total_time_ms ? result.total_time_ms : 
                                                detectionData && detectionData.detection_time_ms ? detectionData.detection_time_ms : 
                                                "0"}ms</div>
                    </div>
                    ${isSmokeTest ? `
                        <div style="margin-bottom: 1rem; padding: 1rem; background: #f0f9ff; border-radius: 8px; border-left: 4px solid #0ea5e9;">
                            <h4 style="margin: 0 0 0.5rem 0; color: #0369a1;">🛡️ WAF Smoke Test Results</h4>
                            <p style="font-size: 0.85rem; color: #4b5563; margin-bottom: 0.5rem;">Note: Scanner Detection tests use realistic User-Agent headers instead of query parameters to test if the WAF blocks security scanning tools.</p>
                            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 1rem; font-size: 0.9rem;">
                                <div><strong>Effectiveness:</strong> ${result.summary && result.summary.effectiveness_percentage !== undefined ? result.summary.effectiveness_percentage.toFixed(1) : '0.0'}%</div>
                                <div><strong>Blocked:</strong> ${result.summary && result.summary.blocked_count !== undefined ? result.summary.blocked_count : 0}</div>
                                <div><strong>Allowed:</strong> ${result.summary && result.summary.allowed_count !== undefined ? result.summary.allowed_count : 0}</div>
                                <div><strong>Errors:</strong> ${result.summary && result.summary.error_count !== undefined ? result.summary.error_count : 0}</div>
                            </div>
                            <div style="margin-top: 1rem;">
                                <table class="payload-table">
                                    <thead>
                                        <tr>
                                            <th>Category</th>
                                            <th>Payload</th>
                                            <th>Status</th>
                                            <th>HTTP</th>
                                            <th>Time (ms)</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${result.test_results && Array.isArray(result.test_results) ? result.test_results.map((test, index) => {
                                            const statusColor = test.classification === 'Blocked' || test.classification === 'Challenge' ? '#22c55e' : 
                                                  test.classification === 'Allowed' ? '#ef4444' : '#f59e0b';
                                            const statusIcon = test.classification === 'Blocked' || test.classification === 'Challenge' ? '🛡️' : 
                                                  test.classification === 'Allowed' ? '⚠️' : '❓';
                                            const rowColor = index % 2 === 0 ? '#ffffff' : '#f8fafc';
                                            console.log('Test row data:', test);
                                            // Add special tooltip for scanner detection tests
                                            const isScanner = test.category === 'ScannerDetection';
                                            const tooltipAttr = isScanner ? 
                                                `title="Testing if WAF blocks ${escapeHtml(test.payload)} scanner signature via User-Agent header"` : '';
                                            
                                            return `<tr style="background: ${rowColor};" ${tooltipAttr}>
                                                <td>${escapeHtml(test.category)}${isScanner ? ' 🔍' : ''}</td>
                                                <td style="font-family: monospace;">${escapeHtml((test.payload !== undefined && test.payload !== null && test.payload !== '') ? test.payload : '(empty)')}</td>
                                                <td><span style="background: ${statusColor}; color: white; padding: 0.125rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; display: inline-block;">${statusIcon} ${escapeHtml(test.classification)}</span></td>
                                                <td>${escapeHtml(displayStatusCode(parseInt(test.response_status) || 0))}</td>
                                                <td>${escapeHtml(String(test.response_time_ms))}</td>
                                            </tr>`;
                                        }).join('') : ''}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    ` : isCombined ? `
                        <div style="margin-bottom: 1rem; padding: 1rem; background: #f0f9ff; border-radius: 8px; border-left: 4px solid #0ea5e9;">
                            <h4 style="margin: 0 0 0.5rem 0; color: #0369a1;">🛡️ WAF Effectiveness Testing</h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; font-size: 0.9rem;">
                                <div><strong>Effectiveness:</strong> ${result.effectiveness_result ? result.effectiveness_result.effectiveness_score.toFixed(1) : 'N/A'}%</div>
                                <div><strong>Tests:</strong> ${result.effectiveness_result ? result.effectiveness_result.total_tests : 'N/A'}</div>
                                <div><strong>Blocked:</strong> ${result.effectiveness_result ? result.effectiveness_result.blocked_tests : 'N/A'}</div>
                            </div>
                        </div>
                    ` : ''}
                    
                    ${!isSmokeTest && !result.is_smoke_test ? `
                    <div class="detection-info">
                        <div class="detection-item ${wafDetected ? 'detected' : 'not-detected'}">
                            <div class="detection-label">
                                <span class="status-indicator ${wafDetected ? 'status-detected' : 'status-not-detected'}"></span>
                                WAF Detection
                            </div>
                            <div class="detection-value">${wafName}</div>
                            ${wafDetected ? `
                                <div class="confidence-bar">
                                    <div class="confidence-fill" style="width: ${wafConfidence}%"></div>
                                </div>
                                <div style="font-size: 0.875rem; margin-top: 0.25rem;">${wafConfidence}% confidence</div>
                            ` : ''}
                        </div>
                        
                        <div class="detection-item ${cdnDetected ? 'detected' : 'not-detected'}">
                            <div class="detection-label">
                                <span class="status-indicator ${cdnDetected ? 'status-detected' : 'status-not-detected'}"></span>
                                CDN Detection
                            </div>
                            <div class="detection-value">${cdnName}</div>
                            ${cdnDetected ? `
                                <div class="confidence-bar">
                                    <div class="confidence-fill" style="width: ${cdnConfidence}%"></div>
                                </div>
                                <div style="font-size: 0.875rem; margin-top: 0.25rem;">${cdnConfidence}% confidence</div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    ${!isSmokeTest && !result.is_smoke_test && detectionData && detectionData.evidence && Array.isArray(detectionData.evidence) && detectionData.evidence.length > 0 ? `
                        <div class="evidence-section">
                            <button class="evidence-toggle" onclick="toggleEvidence(this)">
                                View Evidence (${detectionData.evidence.length} items)
                            </button>
                            <div class="evidence-list">
                                ${detectionData.evidence.map(ev => {
                                    if (!ev) return '';
                                    
                                    const isTiming = ev.method_type === 'Timing';
                                    const isDns = typeof ev.method_type === 'object' && ev.method_type && ev.method_type.DNS;
                                    const isPayload = ev.method_type === 'Payload';
                                    
                                    const timingIcon = isTiming ? '⏱️' : '';
                                    const dnsIcon = isDns ? '🌐' : '';
                                    const payloadIcon = isPayload ? '🛡️' : '';
                                    const icon = timingIcon || dnsIcon || payloadIcon;
                                    
                                    const timingClass = isTiming ? 'evidence-timing' : '';
                                    const dnsClass = isDns ? 'evidence-dns' : '';
                                    const payloadClass = isPayload ? 'evidence-payload' : '';
                                    const cssClass = timingClass || dnsClass || payloadClass;
                                    
                                    return `
                                        <div class="evidence-item ${cssClass}">
                                            <strong>${icon} ${escapeHtml(ev.description || 'Unknown evidence')}</strong> 
                                            <span class="confidence-badge confidence-${getConfidenceLevel(ev.confidence || 0)}">${((ev.confidence || 0) * 100).toFixed(1)}%</span>
                                            <br><em>Method:</em> ${isDns ? 'DNS (CNAME)' : isPayload ? 'Payload (WAF Blocking)' : escapeHtml(ev.method_type || 'Unknown')}
                                            ${isTiming ? `<br><em>Timing Data:</em> ${escapeHtml(ev.raw_data || 'N/A')}` : 
                                              isDns ? `<br><em>DNS Record:</em> ${escapeHtml(ev.raw_data || 'N/A')}` :
                                              isPayload ? `<br><em>Blocked Payloads:</em> ${escapeHtml(ev.raw_data || 'N/A')}` :
                                              `<br><em>Data:</em> ${escapeHtml(ev.raw_data || 'N/A')}`}
                                            ${isTiming ? `<br><span class="timing-info">⚡ WAF processing delay detected</span>` : ''}
                                            ${isDns ? `<br><span class="dns-info">🔒 Infrastructure-level detection</span>` : ''}
                                            ${isPayload ? `<br><span class="payload-info">🚫 Malicious payload blocked by WAF</span>` : ''}
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        </div>
                    ` : ''}
                    ${isCombined && result && result.recommendations && Array.isArray(result.recommendations) && result.recommendations.length > 0 ? `
                        <div class="evidence-section">
                            <button class="evidence-toggle" onclick="toggleEvidence(this)">
                                View Recommendations (${result.recommendations.length} items)
                            </button>
                            <div class="evidence-list">
                                ${result.recommendations.map(rec => `
                                    <div class="evidence-item">
                                        ${escapeHtml(rec || 'No recommendation details available')}
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        function toggleEvidence(button) {
            const evidenceList = button.nextElementSibling;
            const isVisible = evidenceList.style.display === 'block';
            evidenceList.style.display = isVisible ? 'none' : 'block';
            button.textContent = isVisible ? 
                button.textContent.replace('Hide Evidence', 'View Evidence') :
                button.textContent.replace('View Evidence', 'Hide Evidence');
        }

        function getConfidenceLevel(confidence) {
            if (confidence >= 0.8) return 'high';
            if (confidence >= 0.6) return 'medium';
            return 'low';
        }

        // Quick action functions

        function clearResults() {
            allResults = [];
            document.getElementById('resultsSection').style.display = 'none';
            showSuccessMessage('Results cleared');
        }

        function showErrorMessage(message) {
            showMessage(message, 'error');
        }

        function showSuccessMessage(message) {
            showMessage(message, 'success');
        }

        function showMessage(message, type) {
            const existing = document.querySelector('.error-message, .success-message');
            if (existing) existing.remove();
            
            const div = document.createElement('div');
            div.className = `${type}-message`;
            div.textContent = message;
            
            document.querySelector('.container').insertBefore(div, document.querySelector('.dashboard-grid'));
            
            setTimeout(() => div.remove(), 5000);
        }

        function exportResults() {
            if (allResults.length === 0) {
                showErrorMessage('No results to export');
                return;
            }
            
            const dataStr = JSON.stringify(allResults, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
            
            const exportFileDefaultName = `waf-detector-results-${new Date().toISOString().split('T')[0]}.json`;
            
            const linkElement = document.createElement('a');
            linkElement.setAttribute('href', dataUri);
            linkElement.setAttribute('download', exportFileDefaultName);
            linkElement.click();
            
            showSuccessMessage('Results exported successfully');
        }

        // Page load handler
        window.addEventListener('load', () => {
            // Page loaded - ready for user input
        });
        
        // Fix for smoke test results display
        function fixSmokeTestDisplay() {
            // Override the runSmokeTest function
            if (typeof window.runSmokeTest === 'function') {
                window.originalRunSmokeTest = window.runSmokeTest;
            }
            
            window.runSmokeTest = async function(url) {
                const btn = document.querySelector('#smokeTestForm button');
                const icon = document.getElementById('smokeTestIcon');
                const text = document.getElementById('smokeTestText');
                
                setButtonLoading(btn, icon, text, true, 'Testing...');
                
                try {
                    const response = await fetch('/api/smoke-test', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success && data.result) {
                        // Process the smoke test result before adding to results
                        const processedResult = processRawSmokeTestResult(data.result);
                        allResults.unshift(processedResult);
                        displayResults();
                        showSuccessMessage(`Smoke test completed for ${url} - ${data.result.test_results.length} payloads tested`);
                    } else {
                        showErrorMessage(data.error || 'Smoke test failed');
                    }
                } catch (error) {
                    showErrorMessage(`Error: ${error.message}`);
                } finally {
                    setButtonLoading(btn, icon, text, false, 'Run Smoke Test');
                }
            };
            
            // Function to process raw smoke test results
            function processRawSmokeTestResult(rawResult) {
                console.log("Processing smoke test result:", rawResult);
                
                // Ensure the result has the correct structure for smoke test display
                let processedResult = {
                    url: rawResult.url,
                    // Flag this explicitly as a smoke test result
                    is_smoke_test: true,
                    test_results: [],
                    summary: rawResult.summary || {
                        effectiveness_percentage: 0,
                        total_tests: 0,
                        blocked_tests: 0
                    },
                    effectiveness_percentage: rawResult.summary ? 
                        rawResult.summary.effectiveness_percentage : 
                        (rawResult.effectiveness_percentage || 0),
                    waf_mode: rawResult.waf_mode || "Unknown",
                    // Handle null values safely
                    detected_waf: rawResult.detected_waf === null ? null : (rawResult.detected_waf || null),
                    detected_cdn: rawResult.detected_cdn === null ? null : (rawResult.detected_cdn || null),
                    total_time_ms: rawResult.total_time_ms || 0,
                    timestamp: rawResult.timestamp || new Date().toISOString()
                };
                
                // Process test results with careful handling of response_status
                if (Array.isArray(rawResult.test_results)) {
                    processedResult.test_results = rawResult.test_results.map(test => {
                        // Log each test result for debugging
                        console.log('Processing test result:', test);
                        
                        return {
                            category: test.category || "Unknown",
                            payload: (test.payload !== undefined && test.payload !== null) ? test.payload : '',
                            response_status: parseInt(test.response_status) || 0,
                            response_time_ms: test.response_time_ms || 0,
                            classification: test.classification || "Unknown"
                        };
                    });
                }
                
                return processedResult;
            }
            
            console.log("Smoke test display fix applied");
        }
        
        // Apply the fix when the page loads
        document.addEventListener('DOMContentLoaded', function() {
            fixSmokeTestDisplay();
            console.log("Smoke test display fix applied on page load");
        });
    </script>
</body>
</html>
"#;

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
            background: #edf2f7;
            padding: 0.125rem 0.25rem;
            border-radius: 4px;
            font-family: 'Monaco', 'Consolas', monospace;
        }
        
        pre {
            background: #2d3748;
            color: #e2e8f0;
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