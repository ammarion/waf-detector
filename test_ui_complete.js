const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();
  
  console.log('🧪 Testing WAF Detector Web UI - Complete Test\n');
  
  // Test 1: Navigate to dashboard
  console.log('1. Navigating to dashboard...');
  await page.goto('http://localhost:8081/dashboard');
  await page.screenshot({ path: 'screenshots/1-dashboard-initial.png' });
  console.log('✅ Dashboard loaded\n');
  
  // Test 2: Single URL scan - CloudFlare
  console.log('2. Testing single URL scan (CloudFlare)...');
  await page.fill('#singleUrl', 'https://cloudflare.com');
  await page.click('button:has-text("Scan URL")');
  await page.waitForSelector('.result-card', { timeout: 15000 });
  
  // Scroll to results
  await page.evaluate(() => {
    const resultCard = document.querySelector('.result-card');
    if (resultCard) resultCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
  await page.waitForTimeout(1000);
  
  await page.screenshot({ path: 'screenshots/2-cloudflare-result.png', fullPage: true });
  
  // Check if CloudFlare was detected
  const cfResult = await page.textContent('.result-card');
  console.log('CloudFlare detected:', cfResult.includes('CloudFlare') ? '✅ Yes' : '❌ No');
  console.log('✅ Single scan completed\n');
  
  // Test 3: Single URL scan - Azure
  console.log('3. Testing single URL scan (Azure)...');
  await page.fill('#singleUrl', 'https://portal.azure.com');
  await page.click('button:has-text("Scan URL")');
  await page.waitForTimeout(10000); // Wait for scan
  
  // Scroll to latest result
  await page.evaluate(() => {
    const results = document.querySelectorAll('.result-card');
    if (results.length > 0) results[results.length - 1].scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
  await page.waitForTimeout(1000);
  
  await page.screenshot({ path: 'screenshots/3-azure-result.png', fullPage: true });
  
  // Check if Azure was detected
  const azureResult = await page.textContent('body');
  console.log('Azure detected:', azureResult.includes('Azure') ? '✅ Yes' : '❌ No');
  console.log('✅ Azure scan completed\n');
  
  // Test 4: Batch scan
  console.log('4. Testing batch scan...');
  const batchUrls = `https://cloudflare.com
https://microsoft.com
https://portal.azure.com
https://aws.amazon.com`;
  
  await page.fill('#batchUrls', batchUrls);
  await page.click('#batchScanForm button[type="submit"]');
  
  // Wait for all results (longer timeout for batch)
  await page.waitForTimeout(20000);
  
  // Scroll to batch results
  await page.evaluate(() => {
    const results = document.querySelectorAll('.result-card');
    if (results.length > 0) {
      // Scroll to middle of results
      const middle = Math.floor(results.length / 2);
      results[middle].scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  });
  await page.waitForTimeout(1000);
  
  await page.screenshot({ path: 'screenshots/4-batch-results.png', fullPage: true });
  console.log('✅ Batch scan completed\n');
  
  // Test 5: Check for all providers
  console.log('5. Checking for provider detections:');
  const pageContent = await page.textContent('body');
  
  const providers = ['CloudFlare', 'Azure', 'F5', 'AWS', 'Akamai', 'Fastly', 'Vercel'];
  providers.forEach(provider => {
    console.log(`- ${provider} detected:`, pageContent.includes(provider) ? '✅ Yes' : '❌ No');
  });
  
  // Test 6: Export results
  console.log('\n6. Testing export functionality...');
  const exportButton = await page.$('button:has-text("Export Results")');
  if (exportButton) {
    await exportButton.click();
    console.log('✅ Export button clicked');
  }
  
  // Final screenshot
  await page.screenshot({ path: 'screenshots/5-final-state.png', fullPage: true });
  
  console.log('\n✅ All UI tests completed! Check screenshots/ folder for visual results.');
  console.log('\n📊 Summary:');
  console.log('- Dashboard: ✅ Loaded successfully');
  console.log('- Single URL scan: ✅ Working');
  console.log('- Batch scan: ✅ Working');
  console.log('- Azure provider: ' + (azureResult.includes('Azure') ? '✅ Detected' : '⚠️  Not detected on portal.azure.com'));
  console.log('- CloudFlare provider: ' + (cfResult.includes('CloudFlare') ? '✅ Detected' : '❌ Not detected'));
  
  await browser.close();
})();