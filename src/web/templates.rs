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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ WAF Detector</h1>
            <p>Professional Web Application Firewall & CDN Detection</p>
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
                <h2>🛡️ WAF Effectiveness Testing</h2>
                <p style="margin-bottom: 1rem; color: #666; font-size: 0.95rem;">
                    Combined detection + effectiveness testing with 36 attack payloads
                </p>
                <form id="combinedScanForm">
                    <div class="input-group">
                        <label for="combinedUrl">Enter URL to test:</label>
                        <input type="url" id="combinedUrl" class="input-field" placeholder="https://example.com" required>
                    </div>
                    <button type="submit" class="btn">
                        <span id="combinedScanIcon">🛡️</span>
                        <span id="combinedScanText">Test WAF Effectiveness</span>
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

        // Combined WAF effectiveness testing
        document.getElementById('combinedScanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('combinedUrl').value;
            await scanCombined(url);
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

        async function scanCombined(url) {
            const btn = document.querySelector('#combinedScanForm button');
            const icon = document.getElementById('combinedScanIcon');
            const text = document.getElementById('combinedScanText');
            
            setButtonLoading(btn, icon, text, true, 'Testing...');
            
            try {
                const response = await fetch('/api/combined-scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                
                const data = await response.json();
                
                if (data.success && data.result) {
                    allResults.unshift(data.result);
                    displayResults();
                    showSuccessMessage(`Successfully tested ${url} (Detection + Effectiveness)`);
                } else {
                    showErrorMessage(data.error || 'Combined scan failed');
                }
            } catch (error) {
                showErrorMessage(`Error: ${error.message}`);
            } finally {
                setButtonLoading(btn, icon, text, false, 'Test WAF Effectiveness');
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
                } else if (buttonId === 'combinedScanForm') {
                    icon.innerHTML = '🛡️';
                    text.textContent = customText || 'Test WAF Effectiveness';
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
            // Check if this is a combined result (has detection_result property)
            const isCombined = result.detection_result !== undefined;
            const detectionData = isCombined ? result.detection_result : result;
            
            const wafDetected = detectionData.detected_waf !== null;
            const cdnDetected = detectionData.detected_cdn !== null;
            const wafName = wafDetected ? detectionData.detected_waf.name : 'Not Detected';
            const cdnName = cdnDetected ? detectionData.detected_cdn.name : 'Not Detected';
            const wafConfidence = wafDetected ? (detectionData.detected_waf.confidence * 100).toFixed(1) : 0;
            const cdnConfidence = cdnDetected ? (detectionData.detected_cdn.confidence * 100).toFixed(1) : 0;
            
            return `
                <div class="result-card">
                    <div class="result-header">
                        <div class="result-url">${isCombined ? result.url : detectionData.url}</div>
                        <div class="result-time">${isCombined ? result.total_time_ms : detectionData.detection_time_ms}ms</div>
                    </div>
                    ${isCombined ? `
                        <div style="margin-bottom: 1rem; padding: 1rem; background: #f0f9ff; border-radius: 8px; border-left: 4px solid #0ea5e9;">
                            <h4 style="margin: 0 0 0.5rem 0; color: #0369a1;">🛡️ WAF Effectiveness Testing</h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; font-size: 0.9rem;">
                                <div><strong>Effectiveness:</strong> ${result.effectiveness_result ? result.effectiveness_result.effectiveness_score.toFixed(1) : 'N/A'}%</div>
                                <div><strong>Tests:</strong> ${result.effectiveness_result ? result.effectiveness_result.total_tests : 'N/A'}</div>
                                <div><strong>Blocked:</strong> ${result.effectiveness_result ? result.effectiveness_result.blocked_tests : 'N/A'}</div>
                            </div>
                        </div>
                    ` : ''}
                    
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
                    
                    ${detectionData.evidence && detectionData.evidence.length > 0 ? `
                        <div class="evidence-section">
                            <button class="evidence-toggle" onclick="toggleEvidence(this)">
                                View Evidence (${detectionData.evidence.length} items)
                            </button>
                            <div class="evidence-list">
                                ${detectionData.evidence.map(ev => {
                                    const isTiming = ev.method_type === 'Timing';
                                    const isDns = typeof ev.method_type === 'object' && ev.method_type.DNS;
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
                                            <strong>${icon} ${ev.description}</strong> 
                                            <span class="confidence-badge confidence-${getConfidenceLevel(ev.confidence)}">${(ev.confidence * 100).toFixed(1)}%</span>
                                            <br><em>Method:</em> ${isDns ? 'DNS (CNAME)' : isPayload ? 'Payload (WAF Blocking)' : ev.method_type}
                                            ${isTiming ? `<br><em>Timing Data:</em> ${ev.raw_data}` : 
                                              isDns ? `<br><em>DNS Record:</em> ${ev.raw_data}` :
                                              isPayload ? `<br><em>Blocked Payloads:</em> ${ev.raw_data}` :
                                              `<br><em>Data:</em> ${ev.raw_data}`}
                                            ${isTiming ? `<br><span class="timing-info">⚡ WAF processing delay detected</span>` : ''}
                                            ${isDns ? `<br><span class="dns-info">🔒 Infrastructure-level detection</span>` : ''}
                                            ${isPayload ? `<br><span class="payload-info">🚫 Malicious payload blocked by WAF</span>` : ''}
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        </div>
                    ` : ''}
                    ${isCombined && result.recommendations && result.recommendations.length > 0 ? `
                        <div class="evidence-section">
                            <button class="evidence-toggle" onclick="toggleEvidence(this)">
                                View Recommendations (${result.recommendations.length} items)
                            </button>
                            <div class="evidence-list">
                                ${result.recommendations.map(rec => `
                                    <div class="evidence-item">
                                        ${rec}
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