require('dotenv').config();
const fs = require('fs');
const path = require('path');
const db = require('./db');

async function runAudit() {
  const results = [];
  const logResult = (name, status, details = {}) => {
    results.push({ test: name, status, ...details });
    console.log(`[${status}] ${name}`);
  };

  const API_KEY = process.env.API_KEY || (fs.existsSync('.api_key') ? fs.readFileSync('.api_key', 'utf8').trim() : 'qa_test_key_12345');
  const PORT = process.env.PORT || 3100;
  const BASE_URL = `http://127.0.0.1:${PORT}`;

  console.log("▶ Phase 5 Audit Verification\n");

  try {
    await db.init();

    // 0. Health Check Endpoint
    const healthRes = await fetch(`${BASE_URL}/health`);
    const healthJson = await healthRes.json();
    logResult('Health check endpoint returns 200 OK', healthRes.status === 200 && healthJson.status === 'ok' ? 'PASS' : 'FAIL', { status: healthRes.status, body: healthJson });

    // 1. Authentication and Sessions
    const loginRes = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: 'invalid_key' })
    });
    logResult('Reject invalid credential', loginRes.status === 401 ? 'PASS' : 'FAIL', { status: loginRes.status });

    const loginResValid = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: API_KEY })
    });
    const setCookie = loginResValid.headers.get('set-cookie');
    const hasHttpOnly = setCookie && setCookie.includes('HttpOnly');
    const hasSameSite = setCookie && setCookie.includes('SameSite=Strict');
    
    logResult('Accept valid credential', loginResValid.status === 200 ? 'PASS' : 'FAIL', { status: loginResValid.status });
    logResult('Cookie has HttpOnly', hasHttpOnly ? 'PASS' : 'FAIL');
    logResult('Cookie has SameSite=Strict', hasSameSite ? 'PASS' : 'FAIL');

    // 2. Dashboard access without cookie
    const dashRes = await fetch(`${BASE_URL}/dashboard`, { redirect: 'manual' });
    logResult('Reject unauthenticated /dashboard', dashRes.status === 302 && dashRes.headers.get('location') === '/login' ? 'PASS' : 'FAIL');

    // 3. API access without cookie
    const apiRes = await fetch(`${BASE_URL}/api/records`);
    logResult('Reject unauthenticated API requests', apiRes.status === 401 ? 'PASS' : 'FAIL');

    // 4. API access with Bearer header (instead of ?key=)
    const apiResAuth = await fetch(`${BASE_URL}/api/records`, {
      headers: { 'Authorization': `Bearer ${API_KEY}` }
    });
    logResult('Accept API request with Authorization header', apiResAuth.status === 200 ? 'PASS' : 'FAIL');

    // 5. Data Retention & Database Verification
    const oldDate = new Date();
    oldDate.setDate(oldDate.getDate() - 35); // 35 days ago
    
    await db.insertFingerprint(
      'old_test_id', oldDate.toISOString(), '1.1.1.1', 'Audit-Bot', '', '[]', '[]', '{}'
    );
    
    const checkOld = await db.getFingerprintById('old_test_id');
    logResult('Synthetic old record inserted into database', checkOld ? 'PASS' : 'FAIL');

    // Trigger cleanup
    await db.cleanupFingerprints();

    const checkOldAfter = await db.getFingerprintById('old_test_id');
    logResult('Data retention deletes 30+ days old records', !checkOldAfter ? 'PASS' : 'FAIL');

  } catch (err) {
    console.error(err);
    logResult('Audit Execution', 'FAIL', { error: err.message });
  } finally {
    await db.close();
  }

  console.log("\nWriting results to QA_AUDIT_RESULTS.json");
  fs.writeFileSync('QA_AUDIT_RESULTS.json', JSON.stringify(results, null, 2));
}

runAudit();
