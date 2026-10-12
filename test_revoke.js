require('dotenv').config();
const http = require('http');
const db = require('./db');
const fs = require('fs');

const API_KEY = process.env.API_KEY || (fs.existsSync('.api_key') ? fs.readFileSync('.api_key', 'utf8').trim() : 'qa_test_key_12345');
const PORT = process.env.PORT || 3100;

const login = () => {
  return new Promise((resolve, reject) => {
    const req = http.request(`http://127.0.0.1:${PORT}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        const cookies = res.headers['set-cookie'];
        const token = cookies ? cookies[0].split(';')[0].split('=')[1] : null;
        resolve({ status: res.statusCode, token });
      });
    });
    req.write(JSON.stringify({ key: API_KEY }));
    req.end();
  });
};

const accessDashboard = (token) => {
  return new Promise((resolve) => {
    http.get(`http://127.0.0.1:${PORT}/api/records`, {
      headers: { 'Cookie': `auth_token=${token}` }
    }, (res) => {
      resolve(res.statusCode);
    });
  });
};

(async () => {
  await db.init();

  console.log('1. Authenticating to get "old" session...');
  const oldLogin = await login();
  if (!oldLogin.token) {
    console.error('Failed to login initially');
    process.exit(1);
  }
  
  console.log('2. Verifying old session works...');
  const oldAccess = await accessDashboard(oldLogin.token);
  if (oldAccess !== 200) {
    console.error('Old session failed to access records before revoke');
    process.exit(1);
  }
  
  console.log('3. Revoking ALL sessions in database (simulating manual revoke)...');
  await db.clearSessions();
  
  console.log('4. Verifying old session is now REJECTED...');
  const oldAccessAfterRevoke = await accessDashboard(oldLogin.token);
  if (oldAccessAfterRevoke !== 401) {
    console.error(`Expected 401 Unauthorized, got ${oldAccessAfterRevoke}`);
    process.exit(1);
  }
  console.log('   -> SUCCESS: Old session rejected (401).');
  
  console.log('5. Creating newly authenticated test session...');
  const newLogin = await login();
  if (!newLogin.token) {
    console.error('Failed to login for new session');
    process.exit(1);
  }
  
  console.log('6. Verifying new session works...');
  const newAccess = await accessDashboard(newLogin.token);
  if (newAccess !== 200) {
    console.error(`Expected 200 OK, got ${newAccess}`);
    process.exit(1);
  }
  console.log('   -> SUCCESS: New session accepted (200).');
  
  console.log('\nAll tests passed successfully. The exposed session has been permanently invalidated.');
  await db.close();
  process.exit(0);
})();
