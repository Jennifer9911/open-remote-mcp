import crypto from 'node:crypto';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const BASE = process.env.E2E_BASE ?? 'http://localhost:8790';
const OWNER_PASSWORD = process.env.E2E_PASSWORD ?? 'e2e-password';
const ADMIN_TOKEN = process.env.E2E_ADMIN_TOKEN ?? 'e2e-admin-token';
const ROOT = path.resolve(process.cwd());

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
function form(data) {
  return new URLSearchParams(Object.entries(data).map(([k, v]) => [k, String(v)]));
}
async function asJson(response, label) {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`${label}: HTTP ${response.status} ${JSON.stringify(body)}`);
  return body;
}
function pkce(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

console.log('1/8 discovery');
const metadata = await asJson(await fetch(`${BASE}/.well-known/oauth-authorization-server`), 'metadata');
assert(metadata.code_challenge_methods_supported?.includes('S256'), 'S256 PKCE not advertised');
assert(metadata.scopes_supported?.includes('offline_access'), 'offline_access not advertised');

console.log('2/8 dynamic client registration');
const redirectUri = 'http://127.0.0.1:9876/callback';
const registration = await asJson(await fetch(`${BASE}/oauth/register`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ client_name: 'Open Remote MCP E2E', redirect_uris: [redirectUri] })
}), 'register');
assert(registration.client_id, 'client_id missing');

console.log('3/8 authorization code + PKCE + refresh');
const verifier = crypto.randomBytes(48).toString('base64url');
const challenge = pkce(verifier);
const authorize = await fetch(`${BASE}/oauth/authorize`, {
  method: 'POST',
  redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: form({
    response_type: 'code',
    client_id: registration.client_id,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'mcp offline_access',
    resource: `${BASE}/mcp`,
    state: 'e2e-state',
    password: OWNER_PASSWORD
  })
});
assert(authorize.status === 302, `authorize expected 302, got ${authorize.status}`);
const location = authorize.headers.get('location');
assert(location, 'authorization redirect missing');
const callback = new URL(location);
assert(callback.searchParams.get('state') === 'e2e-state', 'state mismatch');
const code = callback.searchParams.get('code');
assert(code, 'authorization code missing');

const token = await asJson(await fetch(`${BASE}/oauth/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: form({
    grant_type: 'authorization_code',
    client_id: registration.client_id,
    redirect_uri: redirectUri,
    code,
    code_verifier: verifier,
    resource: `${BASE}/mcp`
  })
}), 'token');
assert(token.access_token && token.refresh_token, 'access or refresh token missing');

const refreshed = await asJson(await fetch(`${BASE}/oauth/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: form({
    grant_type: 'refresh_token',
    client_id: registration.client_id,
    refresh_token: token.refresh_token
  })
}), 'refresh');
assert(refreshed.access_token && refreshed.refresh_token, 'refresh rotation failed');

console.log('4/8 device authorization');
const deviceId = 'e2e-device-' + crypto.randomUUID();
const deviceCode = await asJson(await fetch(`${BASE}/oauth/device/code`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ client_id: 'open-remote-agent', device_id: deviceId, device_name: 'E2E Mac', platform: process.platform })
}), 'device-code');
assert(deviceCode.user_code && deviceCode.device_code, 'device code response incomplete');

const approval = await fetch(`${BASE}/device/approve`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: form({ user_code: deviceCode.user_code, password: OWNER_PASSWORD })
});
assert(approval.ok, `device approval failed: ${approval.status}`);

const deviceToken = await asJson(await fetch(`${BASE}/oauth/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: form({
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    device_code: deviceCode.device_code,
    client_id: 'open-remote-agent'
  })
}), 'device-token');
assert(deviceToken.access_token, 'device token missing');

console.log('5/8 start real device agent');
const agent = spawn(process.execPath, ['apps/agent/dist/index.js'], {
  cwd: ROOT,
  env: {
    ...process.env,
    REMOTE_MCP_SERVER: BASE.replace(/^http/, 'ws') + '/agent',
    PUBLIC_BASE_URL: BASE,
    DEVICE_ID: deviceId,
    DEVICE_NAME: 'E2E Mac',
    DEVICE_TOKEN: deviceToken.access_token,
    ALLOWED_ROOTS: ROOT,
    ALLOW_SHELL: 'false'
  },
  stdio: ['ignore', 'pipe', 'pipe']
});
let agentOutput = '';
agent.stdout.on('data', chunk => { agentOutput += chunk.toString(); });
agent.stderr.on('data', chunk => { agentOutput += chunk.toString(); });
await Promise.race([
  new Promise((resolve, reject) => {
    const timer = setInterval(() => {
      if (agentOutput.includes('Connected as E2E Mac')) { clearInterval(timer); resolve(null); }
      if (agent.exitCode != null) { clearInterval(timer); reject(new Error('agent exited: ' + agentOutput)); }
    }, 100);
  }),
  new Promise((_, reject) => setTimeout(() => reject(new Error('agent connect timeout: ' + agentOutput)), 5000))
]);

console.log('6/8 MCP over OAuth through relay to agent');
const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), {
  requestInit: { headers: { Authorization: `Bearer ${refreshed.access_token}` } }
});
const client = new Client({ name: 'open-remote-mcp-e2e', version: '0.2.0' });
await client.connect(transport);
const tools = await client.listTools();
assert(tools.tools.some(t => t.name === 'read_file'), 'read_file tool missing');

const deviceList = await client.callTool({ name: 'list_devices', arguments: {} });
assert(JSON.stringify(deviceList).includes(deviceId), 'paired device missing from MCP result');

const read = await client.callTool({
  name: 'read_file',
  arguments: { deviceId, path: path.join(ROOT, 'README.md'), maxBytes: 160 }
});
assert(JSON.stringify(read).includes('Open Remote MCP'), 'relay read_file did not return README');

console.log('7/8 server policy narrowing');
const policyHeaders = { Authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' };
await asJson(await fetch(`${BASE}/api/devices/${encodeURIComponent(deviceId)}/policy`, {
  method: 'PUT',
  headers: policyHeaders,
  body: JSON.stringify({ allowedTools: ['ping', 'list_directory'] })
}), 'set-policy');

let blocked = false;
try {
  const blockedResult = await client.callTool({ name: 'read_file', arguments: { deviceId, path: path.join(ROOT, 'README.md') } });
  blocked = blockedResult.isError === true || JSON.stringify(blockedResult).includes('disabled by server policy');
} catch {
  blocked = true;
}
assert(blocked, 'server policy did not block read_file');

await asJson(await fetch(`${BASE}/api/devices/${encodeURIComponent(deviceId)}/policy`, {
  method: 'PUT',
  headers: policyHeaders,
  body: JSON.stringify({ allowedTools: null })
}), 'restore-policy');

const readAgain = await client.callTool({
  name: 'read_file',
  arguments: { deviceId, path: path.join(ROOT, 'README.md'), maxBytes: 80 }
});
assert(JSON.stringify(readAgain).includes('Open Remote MCP'), 'restored policy did not allow read_file');

console.log('8/8 persisted audit + revocation');
const audit = await asJson(await fetch(`${BASE}/api/activity`, { headers: { Authorization: `Bearer ${ADMIN_TOKEN}` } }), 'audit');
assert(Array.isArray(audit) && audit.some(row => row.deviceId === deviceId && row.tool === 'read_file'), 'audit event missing');

agent.kill('SIGTERM');
await new Promise(resolve => setTimeout(resolve, 250));
await asJson(await fetch(`${BASE}/api/devices/${encodeURIComponent(deviceId)}/revoke`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
}), 'revoke');
const devices = await asJson(await fetch(`${BASE}/api/devices`, { headers: { Authorization: `Bearer ${ADMIN_TOKEN}` } }), 'devices');
assert(devices.some(d => d.id === deviceId && d.status === 'revoked'), 'revocation not persisted');

await client.close();
console.log('E2E PASS');
