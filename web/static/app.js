// Additional JavaScript for WAF Detector
console.log('WAF Detector UI loaded');

// Helper function to render effectiveness charts
function renderEffectivenessChart(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    // Simple chart rendering
    const blocked = data.blocked_tests || 0;
    const allowed = data.allowed_tests || 0;
    const errors = data.error_tests || 0;
    const total = data.total_tests || 1;
    
    const blockedPercent = (blocked / total) * 100;
    const allowedPercent = (allowed / total) * 100;
    const errorPercent = (errors / total) * 100;
    
    container.innerHTML = `
        <div style="display: flex; height: 30px; width: 100%; border-radius: 4px; overflow: hidden;">
            <div style="width: ${blockedPercent}%; background-color: #48bb78;" title="Blocked: ${blocked}"></div>
            <div style="width: ${allowedPercent}%; background-color: #f56565;" title="Allowed: ${allowed}"></div>
            <div style="width: ${errorPercent}%; background-color: #ecc94b;" title="Errors: ${errors}"></div>
        </div>
        <div style="display: flex; justify-content: space-between; margin-top: 5px;">
            <span><span style="color: #48bb78;">■</span> Blocked: ${blocked} (${blockedPercent.toFixed(1)}%)</span>
            <span><span style="color: #f56565;">■</span> Allowed: ${allowed} (${allowedPercent.toFixed(1)}%)</span>
            <span><span style="color: #ecc94b;">■</span> Errors: ${errors} (${errorPercent.toFixed(1)}%)</span>
        </div>
    `;
}

// Add event listener for page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('WAF Detector page loaded');
    
    // Check if we're on the dashboard page
    const combinedScanForm = document.getElementById('combinedScanForm');
    if (combinedScanForm) {
        console.log('Dashboard detected, initializing UI');
    }
});
