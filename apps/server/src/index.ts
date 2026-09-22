import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cors from 'cors';
import { WebSocketServer, WebSocket } from 'ws';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { Store } from './lib/db.js';
import { parseCookies, pkceChallenge, safeEqual, signSession, verifySession } from './lib/security.js';

const PORT = Number(process.env.PORT ?? 8787);
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL ?? `http://localhost:${PORT}`).replace(/\/$/, '');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ?? 'change-me';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? '';
const SESSION_SECRET = process.env.SESSION_SECRET ?? 'change-me-session-secret';
const AGENT_SHARED_TOKEN = process.env.AGENT_SHARED_TOKEN ?? '';
const DATA_DIR = process.env.DATA_DIR ?? path.resolve(process.cwd(), 'data');
const DB_PATH = process.env.DB_PATH ?? path.join(DATA_DIR, 'open-remote-mcp.sqlite');
const IS_HTTPS = PUBLIC_BASE_URL.startsWith('https://');

if (ADMIN_PASSWORD === 'change-me' || SESSION_SECRET === 'change-me-session-secret') {
  console.warn('WARNING: default admin/session secrets are active. Change them before exposing this service.');
}

type LiveDevice = {
  id: string;
  name: string;
  platform?: string;
  ws: WebSocket;
  connectedAt: string;
  capabilities: string[];
  localRoots: string[];
  localShell: boolean;
};
type Pending = {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
  started: number;
  tool: string;
  deviceId: string;
};

const store = new Store(DB_PATH);
const liveDevices = new Map<string, LiveDevice>();
const pending = new Map<string, Pending>();
setInterval(() => store.cleanup(), 60_000).unref();

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));

function adminSession(req: express.Request) {
  const bearer = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (ADMIN_TOKEN && bearer && safeEqual(bearer, ADMIN_TOKEN)) return true;
  const cookie = parseCookies(req.headers.cookie).ormcp_admin;
  return verifySession(cookie, SESSION_SECRET);
}

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!adminSession(req)) return res.status(401).json({ error: 'admin_auth_required' });
  next();
}

function setAdminCookie(res: express.Response) {
  const token = signSession(SESSION_SECRET);
  const secure = IS_HTTPS ? '; Secure' : '';
  res.setHeader('Set-Cookie', `ormcp_admin=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200${secure}`);
}

function escapeHtml(value: unknown) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function page(title: string, body: string) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
  <style>body{margin:0;background:#080b12;color:#dce5f7;font:14px system-ui;display:grid;place-items:center;min-height:100vh}.box{width:min(520px,calc(100vw - 40px));background:#0f1621;border:1px solid #263040;border-radius:18px;padding:28px;box-shadow:0 24px 80px #0008}h1{font-size:24px;margin:0 0 8px}p{color:#8492a8;line-height:1.6}.code{font:700 28px ui-monospace;letter-spacing:.13em;text-align:center;background:#080c12;border:1px solid #273142;padding:18px;border-radius:12px;margin:18px 0;color:#dff973}label{font-size:12px;color:#9aa8bb;display:block;margin:14px 0 6px}input{width:100%;box-sizing:border-box;background:#080c12;border:1px solid #273142;color:#fff;border-radius:9px;padding:11px}button{width:100%;margin-top:16px;border:0;border-radius:9px;background:#dff973;color:#101509;padding:12px;font-weight:750;cursor:pointer}.muted{font-size:12px;color:#627087}.ok{color:#aac87c}</style></head><body><div class="box">${body}</div></body></html>`;
}

function currentDevices() {
  return store.listDevices().map(d => ({
    id: d.id,
    name: d.name,
    platform: d.platform,
    status: d.revoked_at ? 'revoked' : liveDevices.has(d.id) ? 'online' : 'offline',
    lastSeen: liveDevices.has(d.id) ? new Date().toISOString() : d.last_seen,
    createdAt: d.created_at,
    revokedAt: d.revoked_at,
    capabilities: d.capabilities,
    localRoots: d.local_roots,
    localShell: d.local_shell,
    allowedTools: d.allowed_tools
  }));
}

function logActivity(entry: { id: string; deviceId: string; tool: string; ok: boolean; ms: number; summary: string }) {
  store.audit({ ...entry, at: new Date().toISOString() });
}

function pickDevice(deviceId?: string) {
  if (deviceId) return deviceId;
  const online = [...liveDevices.keys()];
  if (online.length === 1) return online[0];
  if (!online.length) throw new Error('No devices are online');
  throw new Error('More than one device is online; provide deviceId');
}

async function invokeDevice(deviceId: string, tool: string, args: Record<string, unknown>) {
  const device = liveDevices.get(deviceId);
  const stored = store.getDevice(deviceId);
  if (!device || device.ws.readyState !== WebSocket.OPEN) throw new Error(`Device ${deviceId} is not online`);
  if (stored?.revoked_at) throw new Error(`Device ${deviceId} is revoked`);
  if (stored?.allowed_tools && !stored.allowed_tools.includes(tool)) throw new Error(`Tool ${tool} is disabled by server policy`);
  if (device.capabilities.length && !device.capabilities.includes(tool)) throw new Error(`Device does not expose tool ${tool}`);

  const id = crypto.randomUUID();
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      logActivity({ id, deviceId, tool, ok: false, ms: 30_000, summary: 'Timed out' });
      reject(new Error(`Timed out waiting for ${deviceId}`));
    }, 30_000);
    pending.set(id, { resolve, reject, timer, started: Date.now(), tool, deviceId });
    device.ws.send(JSON.stringify({ type: 'invoke', id, tool, args }));
  });
}

async function relay(tool: string, args: Record<string, unknown>) {
  const deviceId = pickDevice(args.deviceId as string | undefined);
  const forwarded = { ...args };
  delete forwarded.deviceId;
  return invokeDevice(deviceId, tool, forwarded);
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'open-remote-mcp', version: '0.2.0', now: new Date().toISOString() }));
app.get('/api/session', (req, res) => res.json({ authenticated: adminSession(req) }));
app.post('/api/login', (req, res) => {
  if (!safeEqual(String(req.body?.password ?? ''), ADMIN_PASSWORD)) return res.status(401).json({ error: 'invalid_password' });
  setAdminCookie(res);
  res.json({ ok: true });
});
app.post('/api/logout', (_req, res) => {
  res.setHeader('Set-Cookie', 'ormcp_admin=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});
app.get('/api/devices', requireAdmin, (_req, res) => res.json(currentDevices()));
app.get('/api/activity', requireAdmin, (_req, res) => res.json(store.listActivity(300)));
app.get('/api/config', requireAdmin, (_req, res) => res.json({
  version: '0.2.0',
  publicBaseUrl: PUBLIC_BASE_URL,
  mcpEndpoint: `${PUBLIC_BASE_URL}/mcp`,
  oauthIssuer: PUBLIC_BASE_URL,
  oauthEnabled: true,
  devicePairingEnabled: true,
  persistence: 'sqlite',
  dbPath: DB_PATH
}));
app.put('/api/devices/:id/policy', requireAdmin, (req, res) => {
  const deviceId = String(req.params.id);
  const device = store.getDevice(deviceId);
  if (!device) return res.status(404).json({ error: 'device_not_found' });
  const requested = req.body?.allowedTools;
  if (requested !== null && !Array.isArray(requested)) return res.status(400).json({ error: 'allowedTools_must_be_array_or_null' });
  const capabilities = new Set(device.capabilities);
  const allowedTools = requested === null ? null : requested.map(String).filter((tool: string) => capabilities.has(tool));
  store.setDevicePolicy(deviceId, allowedTools);
  res.json({ ok: true, allowedTools });
});
app.post('/api/devices/:id/revoke', requireAdmin, (req, res) => {
  const deviceId = String(req.params.id);
  if (!store.revokeDevice(deviceId)) return res.status(404).json({ error: 'device_not_found' });
  liveDevices.get(deviceId)?.ws.close(4001, 'Device revoked');
  liveDevices.delete(deviceId);
  res.json({ ok: true });
});

app.get('/.well-known/oauth-authorization-server', (_req, res) => res.json({
  issuer: PUBLIC_BASE_URL,
  authorization_endpoint: `${PUBLIC_BASE_URL}/oauth/authorize`,
  token_endpoint: `${PUBLIC_BASE_URL}/oauth/token`,
  registration_endpoint: `${PUBLIC_BASE_URL}/oauth/register`,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
  token_endpoint_auth_methods_supported: ['none'],
  code_challenge_methods_supported: ['S256'],
  scopes_supported: ['mcp', 'offline_access']
}));
const protectedResourceMetadata = {
  resource: `${PUBLIC_BASE_URL}/mcp`,
  authorization_servers: [PUBLIC_BASE_URL],
  bearer_methods_supported: ['header'],
  scopes_supported: ['mcp', 'offline_access'],
  resource_name: 'Open Remote MCP'
};
app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json(protectedResourceMetadata));
app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => res.json(protectedResourceMetadata));

app.post('/oauth/register', (req, res) => {
  const redirectUris = Array.isArray(req.body?.redirect_uris) ? req.body.redirect_uris.map(String) : [];
  if (!redirectUris.length) return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris is required' });
  try {
    for (const uri of redirectUris) {
      const parsed = new URL(uri);
      const local = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '::1';
      if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) throw new Error('Redirect URI must use HTTPS except localhost');
      if (parsed.hash) throw new Error('Redirect URI must not include a fragment');
    }
  } catch (error: any) {
    return res.status(400).json({ error: 'invalid_redirect_uri', error_description: error.message });
  }
  const { clientId } = store.registerClient({ clientName: String(req.body?.client_name ?? 'MCP client'), redirectUris });
  res.status(201).json({
    client_id: clientId,
    client_name: String(req.body?.client_name ?? 'MCP client'),
    redirect_uris: redirectUris,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code']
  });
});

function validateAuthorize(query: Record<string, any>) {
  const clientId = String(query.client_id ?? '');
  const redirectUri = String(query.redirect_uri ?? '');
  const responseType = String(query.response_type ?? '');
  const codeChallenge = String(query.code_challenge ?? '');
  const method = String(query.code_challenge_method ?? '');
  const client = store.getClient(clientId);
  const scope = String(query.scope ?? 'mcp');
  const requestedScopes = scope.split(/\s+/).filter(Boolean);
  const resource = String(query.resource ?? `${PUBLIC_BASE_URL}/mcp`);
  if (!client || responseType !== 'code' || method !== 'S256' || !codeChallenge || !client.redirectUris.includes(redirectUri)) return null;
  if (requestedScopes.some(item => !['mcp', 'offline_access'].includes(item)) || !requestedScopes.includes('mcp')) return null;
  if (resource !== `${PUBLIC_BASE_URL}/mcp`) return null;
  return { clientId, redirectUri, codeChallenge, scope, resource, state: String(query.state ?? '') };
}

app.get('/oauth/authorize', (req, res) => {
  const input = validateAuthorize(req.query as any);
  if (!input) return res.status(400).send(page('Invalid OAuth request', '<h1>Invalid OAuth request</h1><p>The client, redirect URI, response type, or PKCE parameters are invalid.</p>'));
  const hidden = Object.entries({ client_id: input.clientId, redirect_uri: input.redirectUri, response_type: 'code', code_challenge: input.codeChallenge, code_challenge_method: 'S256', scope: input.scope, resource: input.resource, state: input.state })
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(v)}">`).join('');
  const password = adminSession(req) ? '' : '<label>Owner password</label><input type="password" name="password" autocomplete="current-password" required>';
  res.send(page('Authorize MCP client', `<h1>Authorize MCP client</h1><p><b>${escapeHtml(store.getClient(input.clientId)?.clientName)}</b> is requesting access to this Remote MCP server.</p><form method="post" action="/oauth/authorize">${hidden}${password}<button type="submit">Authorize access</button></form><p class="muted">PKCE S256 · scope: ${escapeHtml(input.scope)}</p>`));
});

app.post('/oauth/authorize', (req, res) => {
  const input = validateAuthorize(req.body as any);
  if (!input) return res.status(400).send(page('Invalid OAuth request', '<h1>Invalid OAuth request</h1>'));
  if (!adminSession(req)) {
    if (!safeEqual(String(req.body?.password ?? ''), ADMIN_PASSWORD)) return res.status(401).send(page('Authorization failed', '<h1>Authorization failed</h1><p>Incorrect owner password.</p>'));
    setAdminCookie(res);
  }
  const code = store.createAuthCode({ clientId: input.clientId, redirectUri: input.redirectUri, codeChallenge: input.codeChallenge, scope: input.scope });
  const target = new URL(input.redirectUri);
  target.searchParams.set('code', code);
  if (input.state) target.searchParams.set('state', input.state);
  res.redirect(302, target.toString());
});

app.post('/oauth/device/code', (req, res) => {
  const deviceId = String(req.body?.device_id ?? '');
  const deviceName = String(req.body?.device_name ?? '');
  const platform = String(req.body?.platform ?? 'unknown');
  if (!deviceId || !deviceName) return res.status(400).json({ error: 'invalid_request' });
  const created = store.createDeviceCode({ deviceId, deviceName, platform });
  res.json({
    device_code: created.deviceCode,
    user_code: created.userCode,
    verification_uri: `${PUBLIC_BASE_URL}/device`,
    verification_uri_complete: `${PUBLIC_BASE_URL}/device?user_code=${encodeURIComponent(created.userCode)}`,
    expires_in: Math.floor((created.expiresAt - Date.now()) / 1000),
    interval: created.interval
  });
});

app.get('/device', (req, res) => {
  const userCode = String(req.query.user_code ?? '').toUpperCase();
  const record = userCode ? store.getDeviceCodeByUserCode(userCode) : null;
  const details = record ? `<p>Pair <b>${escapeHtml(record.device_name)}</b> (${escapeHtml(record.platform)}) with this server.</p><div class="code">${escapeHtml(userCode)}</div>` : '<p>Enter the code displayed by the device agent.</p>';
  const codeInput = record ? `<input type="hidden" name="user_code" value="${escapeHtml(userCode)}">` : '<label>Pairing code</label><input name="user_code" placeholder="ABCD-EFGH" required>';
  const password = adminSession(req) ? '' : '<label>Owner password</label><input type="password" name="password" autocomplete="current-password" required>';
  res.send(page('Pair device', `<h1>Pair a device</h1>${details}<form method="post" action="/device/approve">${codeInput}${password}<button type="submit">Approve device</button></form>`));
});

app.post('/device/approve', (req, res) => {
  if (!adminSession(req)) {
    if (!safeEqual(String(req.body?.password ?? ''), ADMIN_PASSWORD)) return res.status(401).send(page('Pairing failed', '<h1>Pairing failed</h1><p>Incorrect owner password.</p>'));
    setAdminCookie(res);
  }
  const code = String(req.body?.user_code ?? '').trim().toUpperCase();
  if (!store.approveDeviceCode(code)) return res.status(400).send(page('Pairing failed', '<h1>Pairing failed</h1><p>The pairing code is invalid, expired, or already used.</p>'));
  res.send(page('Device approved', '<h1 class="ok">Device approved</h1><p>You can return to the terminal. The agent will finish pairing automatically.</p>'));
});

app.post('/oauth/token', (req, res) => {
  const grant = String(req.body?.grant_type ?? '');
  if (grant === 'authorization_code') {
    const code = store.consumeAuthCode(String(req.body?.code ?? ''));
    const clientId = String(req.body?.client_id ?? '');
    const redirectUri = String(req.body?.redirect_uri ?? '');
    const verifier = String(req.body?.code_verifier ?? '');
    const resource = String(req.body?.resource ?? `${PUBLIC_BASE_URL}/mcp`);
    if (!code || code.clientId !== clientId || code.redirectUri !== redirectUri || resource !== `${PUBLIC_BASE_URL}/mcp` || !verifier || pkceChallenge(verifier) !== code.codeChallenge) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    const tokens = store.issueUserTokens(clientId, code.scope);
    return res.json({ access_token: tokens.accessToken, token_type: 'Bearer', expires_in: tokens.expiresIn, refresh_token: tokens.refreshToken, scope: tokens.scope });
  }
  if (grant === 'refresh_token') {
    const tokens = store.refreshUserToken(String(req.body?.refresh_token ?? ''), String(req.body?.client_id ?? ''));
    if (!tokens) return res.status(400).json({ error: 'invalid_grant' });
    return res.json({ access_token: tokens.accessToken, token_type: 'Bearer', expires_in: tokens.expiresIn, refresh_token: tokens.refreshToken, scope: tokens.scope });
  }
  if (grant === 'urn:ietf:params:oauth:grant-type:device_code') {
    const result = store.exchangeDeviceCode(String(req.body?.device_code ?? ''));
    if (result.status === 'pending') return res.status(400).json({ error: 'authorization_pending' });
    if (result.status === 'expired') return res.status(400).json({ error: 'expired_token' });
    if (result.status !== 'approved') return res.status(400).json({ error: 'access_denied' });
    return res.json({ access_token: result.token, token_type: 'Bearer', scope: 'device' });
  }
  return res.status(400).json({ error: 'unsupported_grant_type' });
});

const nodeServer = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

nodeServer.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  if (url.pathname !== '/agent') return socket.destroy();
  const deviceId = url.searchParams.get('deviceId') ?? '';
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') ?? url.searchParams.get('token') ?? '';
  const legacy = !!AGENT_SHARED_TOKEN && safeEqual(token, AGENT_SHARED_TOKEN);
  if (!deviceId || (!legacy && !store.validateDeviceToken(deviceId, token))) return socket.destroy();
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

wss.on('connection', (ws, req) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  const id = url.searchParams.get('deviceId')!;
  const name = url.searchParams.get('name') ?? id;
  const platform = url.searchParams.get('platform') ?? undefined;
  const live: LiveDevice = { id, name, platform, ws, connectedAt: new Date().toISOString(), capabilities: [], localRoots: [], localShell: false };
  liveDevices.set(id, live);

  ws.on('message', raw => {
    let msg: any;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (msg.type === 'hello') {
      live.capabilities = Array.isArray(msg.capabilities) ? msg.capabilities.map(String) : [];
      live.localRoots = Array.isArray(msg.localRoots) ? msg.localRoots.map(String) : [];
      live.localShell = !!msg.localShell;
      store.updateDeviceMeta({ id, name, platform, capabilities: live.capabilities, localRoots: live.localRoots, localShell: live.localShell });
      return;
    }
    if (msg.type === 'result' && msg.id) {
      const p = pending.get(msg.id);
      if (!p) return;
      clearTimeout(p.timer);
      pending.delete(msg.id);
      const ms = Date.now() - p.started;
      logActivity({ id: msg.id, deviceId: p.deviceId, tool: p.tool, ok: !!msg.ok, ms, summary: msg.ok ? 'Completed' : String(msg.error ?? 'Failed') });
      msg.ok ? p.resolve(msg.result) : p.reject(new Error(String(msg.error ?? 'Agent error')));
    }
  });

  ws.on('close', () => {
    if (liveDevices.get(id)?.ws === ws) liveDevices.delete(id);
    store.updateDeviceMeta({ id, name, platform, capabilities: live.capabilities, localRoots: live.localRoots, localShell: live.localShell });
  });
});

function createMcpServer() {
  const mcp = new McpServer({ name: 'open-remote-mcp', version: '0.2.0' });
  mcp.registerTool('list_devices', { description: 'List paired remote devices', inputSchema: {} }, async () => ({
    content: [{ type: 'text', text: JSON.stringify(currentDevices(), null, 2) }]
  }));
  mcp.registerTool('ping_device', { description: 'Ping a remote device', inputSchema: { deviceId: z.string().optional() } }, async ({ deviceId }) => ({
    content: [{ type: 'text', text: JSON.stringify(await relay('ping', { deviceId })) }]
  }));
  mcp.registerTool('list_directory', { description: 'List a directory on a remote device', inputSchema: { path: z.string(), deviceId: z.string().optional() } }, async args => ({
    content: [{ type: 'text', text: JSON.stringify(await relay('list_directory', args), null, 2) }]
  }));
  mcp.registerTool('read_file', { description: 'Read a UTF-8 text file from a remote device', inputSchema: { path: z.string(), deviceId: z.string().optional(), maxBytes: z.number().int().positive().max(2_000_000).optional() } }, async args => ({
    content: [{ type: 'text', text: String(await relay('read_file', args)) }]
  }));
  mcp.registerTool('write_file', { description: 'Write a UTF-8 text file on a remote device', inputSchema: { path: z.string(), content: z.string(), deviceId: z.string().optional() } }, async args => ({
    content: [{ type: 'text', text: JSON.stringify(await relay('write_file', args)) }]
  }));
  mcp.registerTool('run_command', { description: 'Run a shell command when local shell access and server policy both allow it', inputSchema: { command: z.string(), cwd: z.string().optional(), timeoutMs: z.number().int().min(100).max(120000).optional(), deviceId: z.string().optional() } }, async args => ({
    content: [{ type: 'text', text: JSON.stringify(await relay('run_command', args), null, 2) }]
  }));
  return mcp;
}

function validMcpToken(req: express.Request) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') ?? '';
  if (ADMIN_TOKEN && token && safeEqual(token, ADMIN_TOKEN)) return true;
  return !!store.validateAccessToken(token);
}

app.post('/mcp', async (req, res) => {
  if (!validMcpToken(req)) {
    res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource/mcp", scope="mcp"`);
    return res.status(401).json({ error: 'invalid_token' });
  }
  const mcp = createMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  try {
    await mcp.connect(transport);
    await transport.handleRequest(req, res, req.body);
    res.on('close', () => { transport.close(); mcp.close(); });
  } catch (error) {
    console.error('Error handling MCP request:', error);
    if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
  }
});
app.get('/mcp', (req, res) => {
  if (!validMcpToken(req)) {
    res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource/mcp", scope="mcp"`);
    return res.status(401).end();
  }
  res.status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null });
});
app.delete('/mcp', (_req, res) => res.status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null }));

const here = path.dirname(fileURLToPath(import.meta.url));
const webDist = path.resolve(here, '../../web/dist');
if (fs.existsSync(webDist)) {
  app.use(express.static(webDist));
  app.use((req, res, next) => {
    if (req.method !== 'GET' || req.path.startsWith('/api/') || req.path.startsWith('/oauth/') || req.path.startsWith('/.well-known/') || req.path === '/mcp' || req.path === '/device') return next();
    res.sendFile(path.join(webDist, 'index.html'));
  });
}

nodeServer.listen(PORT, () => {
  console.log(`Open Remote MCP v0.2.0 listening on ${PUBLIC_BASE_URL}`);
  console.log(`SQLite: ${DB_PATH}`);
});
