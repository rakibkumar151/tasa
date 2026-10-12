const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');

test('Crypto Protocol Verification', async (t) => {
  // Wait for server to be ready
  await new Promise(r => setTimeout(r, 1000));

  let pubKeyInfo;
  
  await t.test('Fetch Public Key', async () => {
    pubKeyInfo = await new Promise((resolve) => {
      http.get('http://127.0.0.1:3100/crypto/public-key', (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve(JSON.parse(data)));
      });
    });
    assert.strictEqual(pubKeyInfo.version, '1.0');
    assert.ok(pubKeyInfo.publicKey);
  });

  const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const rsaKey = crypto.createPublicKey({
    key: Buffer.from(pubKeyInfo.publicKey, 'base64'),
    format: 'der',
    type: 'spki'
  });

  const generateValidPayload = (dataStr, overrideNonce, overrideTs) => {
    const aesKey = crypto.randomBytes(32);
    const wrappedKey = crypto.publicEncrypt({
      key: rsaKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, aesKey);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    
    const nonce = overrideNonce || b64url(crypto.randomBytes(16));
    const ts = overrideTs || Date.now().toString();
    const aad = Buffer.from('version=' + pubKeyInfo.version + '&keyId=' + pubKeyInfo.keyId + '&nonce=' + nonce + '&ts=' + ts, 'utf8');
    cipher.setAAD(aad);

    let ciphertext = cipher.update(dataStr, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final(), cipher.getAuthTag()]);

    return {
      version: pubKeyInfo.version,
      keyId: pubKeyInfo.keyId,
      nonce: nonce,
      ts: ts,
      iv: b64url(iv),
      encryptedKey: b64url(wrappedKey),
      ciphertext: b64url(ciphertext)
    };
  };

  const sendPost = (payload) => {
    return new Promise((resolve) => {
      const req = http.request('http://127.0.0.1:3100/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      }, (res) => resolve(res.statusCode));
      req.write(JSON.stringify(payload));
      req.end();
    });
  };

  await t.test('Valid Payload', async () => {
    const payload = generateValidPayload('{"test": 123}');
    const status = await sendPost(payload);
    assert.strictEqual(status, 204);
  });

  await t.test('Replayed request rejected', async () => {
    const payload = generateValidPayload('{"test": 123}');
    const status1 = await sendPost(payload);
    assert.strictEqual(status1, 204);
    
    // Send EXACT same payload again (same nonce)
    const status2 = await sendPost(payload);
    assert.strictEqual(status2, 400); // Replay detected
  });

  await t.test('Expired timestamp rejected', async () => {
    const oldTs = (Date.now() - 10 * 60 * 1000).toString(); // 10 minutes ago
    const payload = generateValidPayload('{"test": 123}', null, oldTs);
    const status = await sendPost(payload);
    assert.strictEqual(status, 400);
  });

  await t.test('Future timestamp (clock skew) rejected', async () => {
    const futureTs = (Date.now() + 2 * 60 * 1000).toString(); // 2 minutes in future (>60s allowed)
    const payload = generateValidPayload('{"test": 123}', null, futureTs);
    const status = await sendPost(payload);
    assert.strictEqual(status, 400);
  });

  await t.test('Plaintext rejection', async () => {
    const status = await sendPost({ test: 123 });
    assert.strictEqual(status, 400); // Because envelope is missing
  });

  await t.test('Modified ciphertext (Tag invalid)', async () => {
    const payload = generateValidPayload('{"test": 123}');
    const buf = Buffer.from(payload.ciphertext, 'base64url');
    buf[0] = buf[0] ^ 1; // alter 1 bit
    payload.ciphertext = b64url(buf);
    const status = await sendPost(payload);
    assert.strictEqual(status, 400);
  });

  await t.test('Invalid IV length', async () => {
    const payload = generateValidPayload('{"test": 123}');
    payload.iv = b64url(crypto.randomBytes(10)); // 10 bytes instead of 12
    const status = await sendPost(payload);
    assert.strictEqual(status, 400);
  });

  await t.test('Invalid AAD (Version mismatch)', async () => {
    const payload = generateValidPayload('{"test": 123}');
    payload.version = '2.0';
    const status = await sendPost(payload);
    assert.strictEqual(status, 400);
  });

  await t.test('Wrong / Unknown keyId', async () => {
    const payload = generateValidPayload('{"test": 123}');
    payload.keyId = 'wrong-key';
    const status = await sendPost(payload);
    assert.strictEqual(status, 400);
  });
  
  await t.test('Missing envelope fields', async () => {
    const payload = generateValidPayload('{"test": 123}');
    delete payload.iv;
    const status = await sendPost(payload);
    assert.strictEqual(status, 400);
  });
});
