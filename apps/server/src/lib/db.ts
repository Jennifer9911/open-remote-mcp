import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { randomToken, sha256 } from './security.js';

export type DeviceRow = {
  id: string;
  name: string;
  platform: string | null;
  created_at: string;
  last_seen: string | null;
  revoked_at: string | null;
  capabilities: string[];
  local_roots: string[];
  local_shell: boolean;
  allowed_tools: string[] | null;
};

function nowIso() {
  return new Date().toISOString();
}

function asJsonArray(value: unknown): string[] {
  if (!value || typeof value !== 'string') return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

export class Store {
  readonly db: DatabaseSync;

  constructor(filename: string) {
    fs.mkdirSync(path.dirname(filename), { recursive: true });
    this.db = new DatabaseSync(filename);
    this.db.exec('PRAGMA journal_mode=WAL;');
    this.db.exec('PRAGMA foreign_keys=ON;');
    this.migrate();
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_name TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS auth_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        scope TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS access_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS device_codes (
        code_hash TEXT PRIMARY KEY,
        user_code TEXT UNIQUE NOT NULL,
        device_id TEXT NOT NULL,
        device_name TEXT NOT NULL,
        platform TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        expires_at INTEGER NOT NULL,
        interval_sec INTEGER NOT NULL DEFAULT 3,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        platform TEXT,
        token_hash TEXT,
        created_at TEXT NOT NULL,
        last_seen TEXT,
        revoked_at TEXT,
        capabilities TEXT NOT NULL DEFAULT '[]',
        local_roots TEXT NOT NULL DEFAULT '[]',
        local_shell INTEGER NOT NULL DEFAULT 0,
        allowed_tools TEXT
      );
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        at TEXT NOT NULL,
        device_id TEXT NOT NULL,
        tool TEXT NOT NULL,
        ok INTEGER NOT NULL,
        ms INTEGER NOT NULL,
        summary TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_access_expiry ON access_tokens(expires_at);
      CREATE INDEX IF NOT EXISTS idx_refresh_expiry ON refresh_tokens(expires_at);
      CREATE INDEX IF NOT EXISTS idx_device_user_code ON device_codes(user_code);
      CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_logs(at DESC);
    `);
  }

  cleanup() {
    const now = Date.now();
    this.db.prepare('DELETE FROM auth_codes WHERE expires_at < ?').run(now);
    this.db.prepare('DELETE FROM access_tokens WHERE expires_at < ?').run(now);
    this.db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?').run(now);
    this.db.prepare('DELETE FROM device_codes WHERE expires_at < ?').run(now);
  }

  registerClient(input: { clientName: string; redirectUris: string[] }) {
    const clientId = randomToken('ormcp_client_', 18);
    this.db.prepare('INSERT INTO oauth_clients(client_id, client_name, redirect_uris, created_at) VALUES(?,?,?,?)')
      .run(clientId, input.clientName, JSON.stringify(input.redirectUris), nowIso());
    return { clientId };
  }

  getClient(clientId: string) {
    const row = this.db.prepare('SELECT * FROM oauth_clients WHERE client_id=?').get(clientId) as any;
    if (!row) return null;
    return { clientId: String(row.client_id), clientName: String(row.client_name), redirectUris: asJsonArray(row.redirect_uris) };
  }

  createAuthCode(input: { clientId: string; redirectUri: string; codeChallenge: string; scope: string }) {
    const code = randomToken('ormcp_code_', 30);
    this.db.prepare('INSERT INTO auth_codes(code_hash,client_id,redirect_uri,code_challenge,scope,expires_at) VALUES(?,?,?,?,?,?)')
      .run(sha256(code), input.clientId, input.redirectUri, input.codeChallenge, input.scope, Date.now() + 5 * 60_000);
    return code;
  }

  consumeAuthCode(code: string) {
    const hash = sha256(code);
    const row = this.db.prepare('SELECT * FROM auth_codes WHERE code_hash=?').get(hash) as any;
    if (!row || Number(row.expires_at) < Date.now()) return null;
    this.db.prepare('DELETE FROM auth_codes WHERE code_hash=?').run(hash);
    return {
      clientId: String(row.client_id),
      redirectUri: String(row.redirect_uri),
      codeChallenge: String(row.code_challenge),
      scope: String(row.scope)
    };
  }

  issueUserTokens(clientId: string, scope: string) {
    const accessToken = randomToken('ormcp_at_', 32);
    const refreshToken = randomToken('ormcp_rt_', 32);
    const accessExpires = Date.now() + 60 * 60_000;
    const refreshExpires = Date.now() + 30 * 24 * 60 * 60_000;
    const created = nowIso();
    this.db.prepare('INSERT INTO access_tokens(token_hash,client_id,scope,expires_at,created_at) VALUES(?,?,?,?,?)')
      .run(sha256(accessToken), clientId, scope, accessExpires, created);
    this.db.prepare('INSERT INTO refresh_tokens(token_hash,client_id,scope,expires_at,created_at) VALUES(?,?,?,?,?)')
      .run(sha256(refreshToken), clientId, scope, refreshExpires, created);
    return { accessToken, refreshToken, expiresIn: 3600, scope };
  }

  refreshUserToken(refreshToken: string, clientId: string) {
    const hash = sha256(refreshToken);
    const row = this.db.prepare('SELECT * FROM refresh_tokens WHERE token_hash=?').get(hash) as any;
    if (!row || Number(row.expires_at) < Date.now() || String(row.client_id) !== clientId) return null;
    this.db.prepare('DELETE FROM refresh_tokens WHERE token_hash=?').run(hash);
    return this.issueUserTokens(clientId, String(row.scope));
  }

  validateAccessToken(token: string) {
    const row = this.db.prepare('SELECT * FROM access_tokens WHERE token_hash=?').get(sha256(token)) as any;
    if (!row || Number(row.expires_at) < Date.now()) return null;
    return { clientId: String(row.client_id), scope: String(row.scope) };
  }

  createDeviceCode(meta: { deviceId: string; deviceName: string; platform: string }) {
    const deviceCode = randomToken('ormcp_dc_', 32);
    let userCode = '';
    for (let i = 0; i < 20; i++) {
      const raw = randomToken('', 6).replace(/[^A-Z0-9]/gi, '').toUpperCase().slice(0, 8);
      userCode = raw.slice(0, 4) + '-' + raw.slice(4, 8);
      const exists = this.db.prepare('SELECT 1 FROM device_codes WHERE user_code=?').get(userCode);
      if (!exists) break;
    }
    const expiresAt = Date.now() + 10 * 60_000;
    this.db.prepare('INSERT INTO device_codes(code_hash,user_code,device_id,device_name,platform,status,expires_at,interval_sec,created_at) VALUES(?,?,?,?,?,?,?,?,?)')
      .run(sha256(deviceCode), userCode, meta.deviceId, meta.deviceName, meta.platform, 'pending', expiresAt, 3, nowIso());
    return { deviceCode, userCode, expiresAt, interval: 3 };
  }

  getDeviceCodeByUserCode(userCode: string) {
    const row = this.db.prepare('SELECT * FROM device_codes WHERE user_code=?').get(userCode.toUpperCase()) as any;
    if (!row || Number(row.expires_at) < Date.now()) return null;
    return row;
  }

  approveDeviceCode(userCode: string) {
    const row = this.getDeviceCodeByUserCode(userCode);
    if (!row || row.status !== 'pending') return false;
    this.db.prepare('UPDATE device_codes SET status=? WHERE user_code=?').run('approved', userCode.toUpperCase());
    return true;
  }

  exchangeDeviceCode(deviceCode: string) {
    const hash = sha256(deviceCode);
    const row = this.db.prepare('SELECT * FROM device_codes WHERE code_hash=?').get(hash) as any;
    if (!row || Number(row.expires_at) < Date.now()) return { status: 'expired' as const };
    if (row.status === 'pending') return { status: 'pending' as const, interval: Number(row.interval_sec) };
    if (row.status !== 'approved') return { status: 'denied' as const };

    const token = randomToken('ormcp_dev_', 32);
    const deviceId = String(row.device_id);
    const existing = this.db.prepare('SELECT id FROM devices WHERE id=?').get(deviceId);
    if (existing) {
      this.db.prepare('UPDATE devices SET name=?,platform=?,token_hash=?,revoked_at=NULL WHERE id=?')
        .run(String(row.device_name), String(row.platform), sha256(token), deviceId);
    } else {
      this.db.prepare('INSERT INTO devices(id,name,platform,token_hash,created_at) VALUES(?,?,?,?,?)')
        .run(deviceId, String(row.device_name), String(row.platform), sha256(token), nowIso());
    }
    this.db.prepare('DELETE FROM device_codes WHERE code_hash=?').run(hash);
    return { status: 'approved' as const, token, deviceId };
  }

  validateDeviceToken(deviceId: string, token: string) {
    const row = this.db.prepare('SELECT token_hash,revoked_at FROM devices WHERE id=?').get(deviceId) as any;
    return !!row && !row.revoked_at && !!row.token_hash && String(row.token_hash) === sha256(token);
  }

  updateDeviceMeta(input: { id: string; name: string; platform?: string; capabilities?: string[]; localRoots?: string[]; localShell?: boolean }) {
    const existing = this.db.prepare('SELECT id FROM devices WHERE id=?').get(input.id);
    if (!existing) {
      this.db.prepare('INSERT INTO devices(id,name,platform,created_at,last_seen,capabilities,local_roots,local_shell) VALUES(?,?,?,?,?,?,?,?)')
        .run(input.id, input.name, input.platform ?? null, nowIso(), nowIso(), JSON.stringify(input.capabilities ?? []), JSON.stringify(input.localRoots ?? []), input.localShell ? 1 : 0);
      return;
    }
    this.db.prepare('UPDATE devices SET name=?,platform=?,last_seen=?,capabilities=?,local_roots=?,local_shell=? WHERE id=?')
      .run(input.name, input.platform ?? null, nowIso(), JSON.stringify(input.capabilities ?? []), JSON.stringify(input.localRoots ?? []), input.localShell ? 1 : 0, input.id);
  }

  listDevices(): DeviceRow[] {
    const rows = this.db.prepare('SELECT * FROM devices ORDER BY COALESCE(last_seen, created_at) DESC').all() as any[];
    return rows.map(row => ({
      id: String(row.id),
      name: String(row.name),
      platform: row.platform ? String(row.platform) : null,
      created_at: String(row.created_at),
      last_seen: row.last_seen ? String(row.last_seen) : null,
      revoked_at: row.revoked_at ? String(row.revoked_at) : null,
      capabilities: asJsonArray(row.capabilities),
      local_roots: asJsonArray(row.local_roots),
      local_shell: !!row.local_shell,
      allowed_tools: row.allowed_tools == null ? null : asJsonArray(row.allowed_tools)
    }));
  }

  getDevice(deviceId: string) {
    return this.listDevices().find(d => d.id === deviceId) ?? null;
  }

  setDevicePolicy(deviceId: string, allowedTools: string[] | null) {
    const result = this.db.prepare('UPDATE devices SET allowed_tools=? WHERE id=?')
      .run(allowedTools == null ? null : JSON.stringify([...new Set(allowedTools)]), deviceId);
    return Number(result.changes) > 0;
  }

  revokeDevice(deviceId: string) {
    const result = this.db.prepare('UPDATE devices SET revoked_at=?,token_hash=NULL WHERE id=?').run(nowIso(), deviceId);
    return Number(result.changes) > 0;
  }

  audit(entry: { id: string; at: string; deviceId: string; tool: string; ok: boolean; ms: number; summary: string }) {
    this.db.prepare('INSERT INTO audit_logs(id,at,device_id,tool,ok,ms,summary) VALUES(?,?,?,?,?,?,?)')
      .run(entry.id, entry.at, entry.deviceId, entry.tool, entry.ok ? 1 : 0, entry.ms, entry.summary);
    this.db.prepare('DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs ORDER BY at DESC LIMIT -1 OFFSET 5000)').run();
  }

  listActivity(limit = 200) {
    const safeLimit = Math.max(1, Math.min(limit, 1000));
    const rows = this.db.prepare('SELECT * FROM audit_logs ORDER BY at DESC LIMIT ?').all(safeLimit) as any[];
    return rows.map(row => ({
      id: String(row.id),
      at: String(row.at),
      deviceId: String(row.device_id),
      tool: String(row.tool),
      ok: !!row.ok,
      ms: Number(row.ms),
      summary: String(row.summary)
    }));
  }
}
