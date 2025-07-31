const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();
  
  console.log('🧪 Testing WAF Detector Web UI...\n');
  
  // Test 1: Navigate to dashboard
  console.log('1. Navigating to dashboard...');
  await page.goto('http://localhost:8081/dashboard');
  await page.screenshot({ path: 'screenshots/dashboard.png' });
  console.log('✅ Dashboard loaded\n');
  
  // Test 2: Single URL scan
  console.log('2. Testing single URL scan...');
  await page.fill('#singleUrl', 'https://cloudflare.com');
  await page.click('button:has-text("Scan URL")');
  await page.waitForSelector('.result-card', { timeout: 15000 });
  await page.screenshot({ path: 'screenshots/single-scan-result.png' });
  console.log('✅ Single scan completed\n');
  
  // Test 3: Batch scan
  console.log('3. Testing batch scan...');
  const batchUrls = `https://cloudflare.com
https://microsoft.com
https://portal.azure.com
https://aws.amazon.com`;
  await page.fill('#batchUrls', batchUrls);
  await page.click('#batchScanForm button[type="submit"]');
  await page.waitForTimeout(15000); // Wait for all results
  await page.screenshot({ path: 'screenshots/batch-scan-results.png' });
  console.log('✅ Batch scan completed\n');
  
  // Test 4: WAF Smoke Test
  console.log('4. Testing WAF smoke test...');
  await page.fill('#smokeTestUrl', 'https://cloudflare.com');
  await page.click('#smokeTestForm button[type="submit"]');
  await page.waitForSelector('.smoke-test-result', { timeout: 30000 });
  await page.screenshot({ path: 'screenshots/smoke-test-result.png' });
  console.log('✅ Smoke test completed\n');
  
  // Test 5: Check for Azure/F5 providers
  const resultText = await page.textContent('body');
  console.log('5. Checking for providers:');
  console.log('- Azure detected:', resultText.includes('Azure'));
  console.log('- F5 detected:', resultText.includes('F5'));
  console.log('- CloudFlare detected:', resultText.includes('CloudFlare'));
  console.log('- AWS detected:', resultText.includes('AWS'));
  
  console.log('\n✅ All UI tests completed! Check screenshots/ folder for results.');
  
  await browser.close();
})();