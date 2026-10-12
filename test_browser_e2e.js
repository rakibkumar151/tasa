const { chromium } = require('playwright');
const fs = require('fs');

async function run() {
  const results = [];
  const logResult = (name, status, details = {}) => {
    results.push({ test: name, status, ...details });
    console.log(`[${status}] ${name}`);
  };

  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    let publicKeyFetched = false;
    let collectPayload = null;
    let collectResponseStatus = null;

    // Route interception for mocking FingerprintJS and avoiding real data collection
    await page.route('**/js/ga.min.js', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/javascript',
        body: `
          window.FingerprintJS = {
            load: async () => ({
              get: async () => ({
                visitorId: 'QA_MOCK_VISITOR_123',
                components: { mock: true }
              })
            })
          };
        `
      });
    });

    // WebRTC interception to prevent real IP leak during test
    await page.addInitScript(() => {
      window.RTCPeerConnection = function() {
        this.createDataChannel = () => {};
        this.createOffer = async () => ({});
        this.setLocalDescription = async () => {};
        this.close = () => {};
      };
      window.navigator.mediaDevices = undefined; // Mock media devices
    });

    page.on('request', request => {
      if (request.url().includes('/crypto/public-key')) {
        publicKeyFetched = true;
      }
      if (request.url().includes('/collect') && request.method() === 'POST') {
        collectPayload = JSON.parse(request.postData());
      }
    });

    page.on('response', async response => {
      if (response.url().includes('/collect') && response.request().method() === 'POST') {
        collectResponseStatus = response.status();
        try {
          const body = await response.text();
          console.log("COLLECT RESPONSE:", collectResponseStatus, body);
        } catch(e) {}
      }
    });

    page.on('pageerror', err => {
      console.error('Browser Page Error:', err.message);
    });

    // OPEN DASHBOARD FIRST TO CAPTURE SSE
    const dashPage = await context.newPage();
    dashPage.on('console', msg => console.log('DASHBOARD CONSOLE:', msg.text()));
    
    // Login First
    await dashPage.goto('http://127.0.0.1:3100/login');
    await dashPage.fill('#key', 'qa_test_key_12345');
    await dashPage.click('button[type="submit"]');
    await dashPage.waitForURL('**/dashboard');
    await dashPage.waitForTimeout(2000); // Give SSE time to connect

    // 1. A. Page and tracker loading
    const response = await page.goto('http://127.0.0.1:3100/', { waitUntil: 'networkidle' });
    logResult('Root page loads successfully', response.status() === 200 ? 'PASS' : 'FAIL', { status: response.status() });

    // Wait for the collect payload to be sent (WebRTC delay + Audio delay)
    await page.waitForTimeout(3000);

    // B. Public-key retrieval
    logResult('Browser fetches the actual public key', publicKeyFetched ? 'PASS' : 'FAIL');

    // C. Real client/server encryption flow
    if (collectPayload) {
      logResult('Real browser sends the envelope to POST /collect', 'PASS');
      const hasAllFields = ['version', 'keyId', 'nonce', 'iv', 'encryptedKey', 'ciphertext'].every(k => k in collectPayload);
      logResult('Expected fields match the implemented schema', hasAllFields ? 'PASS' : 'FAIL', { payloadKeys: Object.keys(collectPayload) });
      logResult('Original synthetic plaintext payload is not present in transmitted request body', (!collectPayload.visitorId) ? 'PASS' : 'FAIL');
      logResult('Response matches the documented success behavior', collectResponseStatus === 204 ? 'PASS' : 'FAIL', { status: collectResponseStatus });
    } else {
      logResult('Real browser sends the envelope to POST /collect', 'FAIL', { error: 'No payload captured' });
    }

    // E. Dashboard and storage
    await dashPage.waitForTimeout(2000);
    try {
      await dashPage.click('.visitor-item');
      await dashPage.waitForTimeout(500);
    } catch(e) {}
    
    const statusText = await dashPage.$eval('#statusText', el => el.textContent).catch(() => 'unknown');
    console.log("DASHBOARD STATUS:", statusText);
    
    const dashboardContent = await dashPage.content();
    fs.writeFileSync('dash_debug.html', dashboardContent);
    await dashPage.screenshot({ path: 'dashboard_screenshot.png' });
    const dashboardText = await dashPage.innerText('body');
    const isRecordVisible = dashboardText.includes('QA_MOCK_VISITOR_123');
    logResult('Dashboard displays the newly accepted synthetic record', isRecordVisible ? 'PASS' : 'FAIL');

  } catch (err) {
    console.error('Test Execution Error:', err);
    logResult('Test Execution', 'FAIL', { error: err.message });
  } finally {
    if (browser) await browser.close();
  }

  // F. Security regression tests (Rate limiting)
  try {
    let tooManyRequests = false;
    for(let i=0; i<35; i++) {
      const res = await fetch('http://127.0.0.1:3100/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}) // malformed, but rate limit triggers first
      });
      if (res.status === 429) {
        tooManyRequests = true;
        break;
      }
    }
    logResult('Excessive requests receive the expected 429 response', tooManyRequests ? 'PASS' : 'FAIL');
  } catch(e) {
    logResult('Excessive requests receive the expected 429 response', 'FAIL', { error: e.message });
  }

  fs.writeFileSync('QA_TEST_RESULTS.json', JSON.stringify(results, null, 2));
  console.log("Wrote QA_TEST_RESULTS.json");
}

run();
