// Fix for smoke test results display
// Add this script to the web interface

// Function to fix smoke test results display
function fixSmokeTestDisplay() {
    // Override the runSmokeTest function
    window.originalRunSmokeTest = window.runSmokeTest;
    
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
        // Create a processed version of the smoke test result
        return {
            url: rawResult.url,
            test_results: rawResult.test_results.map(test => ({
                category: test.category,
                payload: test.payload,
                status: test.classification, // Map classification to status
                status_code: test.response_status,
                response_time_ms: test.response_time_ms
            })),
            effectiveness_percentage: rawResult.summary.effectiveness_percentage,
            waf_mode: rawResult.waf_mode,
            total_time_ms: rawResult.total_time_ms,
            timestamp: rawResult.timestamp
        };
    }
    
    console.log("Smoke test display fix applied");
}

// Apply the fix when the page loads
document.addEventListener('DOMContentLoaded', fixSmokeTestDisplay);
