const path = require('path');
const fs = require('fs');

const TURSO_URL = process.env.TURSO_DATABASE_URL || process.env.LIBSQL_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN || process.env.LIBSQL_AUTH_TOKEN;

let isTurso = false;
let tursoClient = null;
let localDb = null;
let stmts = {};

if (TURSO_URL) {
  isTurso = true;
  const { createClient } = require('@libsql/client');
  tursoClient = createClient({
    url: TURSO_URL,
    authToken: TURSO_TOKEN
  });
} else {
  const { DatabaseSync } = require('node:sqlite');
  const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'fingerprints.db');
  localDb = new DatabaseSync(DB_FILE);
}

async function init() {
  if (isTurso) {
    await tursoClient.execute(`
      CREATE TABLE IF NOT EXISTS fingerprints (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        ip TEXT,
        userAgent TEXT,
        referer TEXT,
        vpn_leak TEXT,
        ip_addresses TEXT,
        data TEXT
      );
    `);
    await tursoClient.execute(`
      CREATE TABLE IF NOT EXISTS seen_nonces (
        nonce TEXT PRIMARY KEY,
        expiresAt INTEGER
      );
    `);
    await tursoClient.execute(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        expiresAt INTEGER
      );
    `);
  } else {
    localDb.exec(`
      CREATE TABLE IF NOT EXISTS fingerprints (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        ip TEXT,
        userAgent TEXT,
        referer TEXT,
        vpn_leak JSON,
        ip_addresses JSON,
        data JSON
      );
      CREATE TABLE IF NOT EXISTS seen_nonces (
        nonce TEXT PRIMARY KEY,
        expiresAt INTEGER
      );
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        expiresAt INTEGER
      );
    `);

    stmts.insertFingerprint = localDb.prepare(`
      INSERT INTO fingerprints (id, timestamp, ip, userAgent, referer, vpn_leak, ip_addresses, data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmts.getFingerprints = localDb.prepare('SELECT * FROM fingerprints ORDER BY timestamp DESC LIMIT ?');
    stmts.getFingerprintById = localDb.prepare('SELECT * FROM fingerprints WHERE id = ?');
    stmts.clearFingerprints = localDb.prepare('DELETE FROM fingerprints');

    stmts.checkNonce = localDb.prepare('SELECT nonce FROM seen_nonces WHERE nonce = ?');
    stmts.insertNonce = localDb.prepare('INSERT INTO seen_nonces (nonce, expiresAt) VALUES (?, ?)');
    stmts.cleanupNonces = localDb.prepare('DELETE FROM seen_nonces WHERE expiresAt < ?');
    stmts.cleanupFingerprints = localDb.prepare("DELETE FROM fingerprints WHERE datetime(timestamp) < datetime('now', '-30 days')");

    stmts.checkSession = localDb.prepare('SELECT token FROM sessions WHERE token = ? AND expiresAt > ?');
    stmts.insertSession = localDb.prepare('INSERT INTO sessions (token, expiresAt) VALUES (?, ?)');
    stmts.deleteSession = localDb.prepare('DELETE FROM sessions WHERE token = ?');
    stmts.clearSessions = localDb.prepare('DELETE FROM sessions');
    stmts.cleanupSessions = localDb.prepare('DELETE FROM sessions WHERE expiresAt < ?');
  }
}

async function insertSession(token, expiresAt) {
  if (isTurso) {
    await tursoClient.execute({
      sql: 'INSERT INTO sessions (token, expiresAt) VALUES (?, ?)',
      args: [token, expiresAt]
    });
  } else {
    stmts.insertSession.run(token, expiresAt);
  }
}

async function checkSession(token, now = Date.now()) {
  if (isTurso) {
    const res = await tursoClient.execute({
      sql: 'SELECT token FROM sessions WHERE token = ? AND expiresAt > ?',
      args: [token, now]
    });
    return res.rows.length > 0 ? res.rows[0] : null;
  } else {
    return stmts.checkSession.get(token, now);
  }
}

async function deleteSession(token) {
  if (isTurso) {
    await tursoClient.execute({
      sql: 'DELETE FROM sessions WHERE token = ?',
      args: [token]
    });
  } else {
    stmts.deleteSession.run(token);
  }
}

async function clearSessions() {
  if (isTurso) {
    await tursoClient.execute('DELETE FROM sessions');
  } else {
    stmts.clearSessions.run();
  }
}

async function cleanupSessions(now = Date.now()) {
  if (isTurso) {
    await tursoClient.execute({
      sql: 'DELETE FROM sessions WHERE expiresAt < ?',
      args: [now]
    });
  } else {
    stmts.cleanupSessions.run(now);
  }
}

async function insertNonce(nonce, expiresAt) {
  if (isTurso) {
    await tursoClient.execute({
      sql: 'INSERT INTO seen_nonces (nonce, expiresAt) VALUES (?, ?)',
      args: [nonce, expiresAt]
    });
  } else {
    stmts.insertNonce.run(nonce, expiresAt);
  }
}

async function cleanupNonces(now = Date.now()) {
  if (isTurso) {
    await tursoClient.execute({
      sql: 'DELETE FROM seen_nonces WHERE expiresAt < ?',
      args: [now]
    });
  } else {
    stmts.cleanupNonces.run(now);
  }
}

async function insertFingerprint(id, timestamp, ip, userAgent, referer, vpn_leak, ip_addresses, data) {
  const vpnLeakStr = typeof vpn_leak === 'string' ? vpn_leak : JSON.stringify(vpn_leak);
  const ipAddrsStr = typeof ip_addresses === 'string' ? ip_addresses : JSON.stringify(ip_addresses);
  const dataStr = typeof data === 'string' ? data : JSON.stringify(data);

  if (isTurso) {
    await tursoClient.execute({
      sql: `INSERT INTO fingerprints (id, timestamp, ip, userAgent, referer, vpn_leak, ip_addresses, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [id, timestamp, ip, userAgent, referer, vpnLeakStr, ipAddrsStr, dataStr]
    });
  } else {
    stmts.insertFingerprint.run(id, timestamp, ip, userAgent, referer, vpnLeakStr, ipAddrsStr, dataStr);
  }
}

function normalizeRecord(row) {
  if (!row) return null;
  return {
    id: row.id,
    timestamp: row.timestamp,
    ip: row.ip,
    userAgent: row.userAgent,
    referer: row.referer,
    vpn_leak: typeof row.vpn_leak === 'string' ? JSON.parse(row.vpn_leak) : row.vpn_leak,
    ip_addresses: typeof row.ip_addresses === 'string' ? JSON.parse(row.ip_addresses) : row.ip_addresses,
    data: typeof row.data === 'string' ? JSON.parse(row.data) : row.data
  };
}

async function getFingerprints(limit = 100) {
  if (isTurso) {
    const res = await tursoClient.execute({
      sql: 'SELECT * FROM fingerprints ORDER BY timestamp DESC LIMIT ?',
      args: [limit]
    });
    return res.rows.map(normalizeRecord);
  } else {
    const rows = stmts.getFingerprints.all(limit);
    return rows.map(normalizeRecord);
  }
}

async function getFingerprintById(id) {
  if (isTurso) {
    const res = await tursoClient.execute({
      sql: 'SELECT * FROM fingerprints WHERE id = ?',
      args: [id]
    });
    return res.rows.length > 0 ? normalizeRecord(res.rows[0]) : null;
  } else {
    const row = stmts.getFingerprintById.get(id);
    return normalizeRecord(row);
  }
}

async function clearFingerprints() {
  if (isTurso) {
    await tursoClient.execute('DELETE FROM fingerprints');
  } else {
    stmts.clearFingerprints.run();
  }
}

async function cleanupFingerprints() {
  if (isTurso) {
    await tursoClient.execute("DELETE FROM fingerprints WHERE datetime(timestamp) < datetime('now', '-30 days')");
  } else {
    stmts.cleanupFingerprints.run();
  }
}

async function close() {
  if (isTurso && tursoClient) {
    tursoClient.close();
  }
}

module.exports = {
  isTurso: () => isTurso,
  init,
  insertSession,
  checkSession,
  deleteSession,
  clearSessions,
  cleanupSessions,
  insertNonce,
  cleanupNonces,
  insertFingerprint,
  getFingerprints,
  getFingerprintById,
  clearFingerprints,
  cleanupFingerprints,
  close
};
