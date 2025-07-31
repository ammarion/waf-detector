const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();
  
  console.log('🧪 WAF Detector Web UI Test\n');
  
  // Navigate to dashboard
  await page.goto('http://localhost:8081/dashboard');
  console.log('✅ Dashboard loaded');
  
  // Test CloudFlare detection
  console.log('\n📍 Testing CloudFlare detection...');
  await page.fill('#singleUrl', 'https://cloudflare.com');
  await page.click('button:has-text("Scan URL")');
  
  // Wait for results section to become visible
  await page.waitForSelector('#resultsSection', { state: 'visible', timeout: 20000 });
  await page.waitForTimeout(2000); // Let results render
  
  // Take screenshot
  await page.screenshot({ path: 'screenshots/cloudflare-full-result.png', fullPage: true });
  
  // Check results
  const results = await page.textContent('#resultsContainer');
  console.log('CloudFlare detected:', results.includes('CloudFlare') ? '✅ Yes' : '❌ No');
  
  // Test Azure detection
  console.log('\n📍 Testing Azure detection...');
  await page.fill('#singleUrl', 'https://portal.azure.com');
  await page.click('button:has-text("Scan URL")');
  await page.waitForTimeout(10000); // Wait for scan
  
  await page.screenshot({ path: 'screenshots/azure-full-result.png', fullPage: true });
  
  const allResults = await page.textContent('#resultsContainer');
  console.log('Azure detected:', allResults.includes('Azure') ? '✅ Yes' : '❌ No');
  
  // Check for F5 false positives
  console.log('F5 false positive on CloudFlare:', allResults.includes('F5') && allResults.includes('cloudflare.com') ? '⚠️  Yes' : '✅ No');
  
  // Test batch scan
  console.log('\n📍 Testing batch scan...');
  await page.fill('#batchUrls', 'https://cloudflare.com\nhttps://microsoft.com\nhttps://aws.amazon.com');
  await page.click('#batchScanForm button[type="submit"]');
  await page.waitForTimeout(15000); // Wait for batch results
  
  await page.screenshot({ path: 'screenshots/batch-full-results.png', fullPage: true });
  
  // Check all providers
  const finalResults = await page.textContent('body');
  console.log('\n📊 Provider detection summary:');
  ['CloudFlare', 'Azure', 'F5', 'AWS', 'Akamai'].forEach(provider => {
    console.log(`- ${provider}:`, finalResults.includes(provider) ? '✅ Detected' : '❌ Not detected');
  });
  
  console.log('\n✅ UI testing complete!');
  
  await browser.close();
})();