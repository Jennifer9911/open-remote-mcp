#!/usr/bin/env node
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import crypto from 'node:crypto';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import WebSocket from 'ws';

const execAsync = promisify(exec);
const SERVER = process.env.REMOTE_MCP_SERVER ?? 'ws://localhost:8787/agent';
const HTTP_BASE = process.env.PUBLIC_BASE_URL ?? (() => {
  const url = new URL(SERVER);
  url.protocol = url.protocol === 'wss:' ? 'https:' : 'http:';
  url.pathname = '';
  url.search = '';
  return url.toString().replace(/\/$/, '');
})();
const CREDENTIALS_PATH = process.env.CREDENTIALS_PATH ?? path.join(os.homedir(), '.open-remote-mcp', 'credentials.json');
const DEVICE_NAME = process.env.DEVICE_NAME ?? os.hostname();
const ALLOW_SHELL = /^(1|true|yes)$/i.test(process.env.ALLOW_SHELL ?? 'false');
const rawRoots = (process.env.ALLOWED_ROOTS ?? process.cwd()).split(path.delimiter).filter(Boolean).map(p => path.resolve(p));
const ALLOWED_ROOTS = rawRoots.map(root => {
  if (!fs.existsSync(root)) throw new Error(`ALLOWED_ROOTS entry does not exist: ${root}`);
  return fs.realpathSync.native(root);
});
const CAPABILITIES = ['ping', 'list_directory', 'read_file', 'write_file', ...(ALLOW_SHELL ? ['run_command'] : [])];

type Credentials = { deviceId: string; token?: string };

function loadCredentials(): Credentials {
  const envId = process.env.DEVICE_ID;
  const envToken = process.env.DEVICE_TOKEN;
  if (envId || envToken) return { deviceId: envId ?? `ormcp_device_${crypto.randomUUID()}`, token: envToken };
  try {
    const parsed = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
    return { deviceId: String(parsed.deviceId), token: parsed.token ? String(parsed.token) : undefined };
  } catch {
    return { deviceId: `ormcp_device_${crypto.randomUUID()}` };
  }
}

function saveCredentials(credentials: Credentials) {
  if (process.env.DEVICE_TOKEN) return;
  fs.mkdirSync(path.dirname(CREDENTIALS_PATH), { recursive: true, mode: 0o700 });
  fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(credentials, null, 2), { mode: 0o600 });
}

function inside(root: string, candidate: string) {
  return candidate === root || candidate.startsWith(root + path.sep);
}

function assertExistingAllowed(target: string) {
  const real = fs.realpathSync.native(path.resolve(target));
  if (!ALLOWED_ROOTS.some(root => inside(root, real))) throw new Error(`Path is outside ALLOWED_ROOTS: ${target}`);
  return real;
}

function assertWritableAllowed(target: string) {
  const resolved = path.resolve(target);
  let parent = path.dirname(resolved);
  while (!fs.existsSync(parent)) {
    const next = path.dirname(parent);
    if (next === parent) break;
    parent = next;
  }
  const realParent = fs.realpathSync.native(parent);
  if (!ALLOWED_ROOTS.some(root => inside(root, realParent))) throw new Error(`Path is outside ALLOWED_ROOTS: ${target}`);
  return resolved;
}

async function invoke(tool: string, args: any) {
  if (tool === 'ping') return { pong: true, at: new Date().toISOString(), hostname: os.hostname() };

  if (tool === 'list_directory') {
    const target = assertExistingAllowed(String(args.path));
    const entries = await fsp.readdir(target, { withFileTypes: true });
    return entries.map(entry => ({
      name: entry.name,
      type: entry.isDirectory() ? 'directory' : entry.isFile() ? 'file' : entry.isSymbolicLink() ? 'symlink' : 'other'
    }));
  }

  if (tool === 'read_file') {
    const target = assertExistingAllowed(String(args.path));
    const max = Math.min(Number(args.maxBytes ?? 512000), 2_000_000);
    const handle = await fsp.open(target, 'r');
    try {
      const stat = await handle.stat();
      if (!stat.isFile()) throw new Error('read_file only supports regular files');
      const size = Math.min(stat.size, max);
      const buffer = Buffer.alloc(size);
      await handle.read(buffer, 0, size, 0);
      return buffer.toString('utf8');
    } finally {
      await handle.close();
    }
  }

  if (tool === 'write_file') {
    const target = assertWritableAllowed(String(args.path));
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.writeFile(target, String(args.content), 'utf8');
    const finalPath = assertExistingAllowed(target);
    return { ok: true, path: finalPath, bytes: Buffer.byteLength(String(args.content)) };
  }

  if (tool === 'run_command') {
    if (!ALLOW_SHELL) throw new Error('Shell access is disabled locally. Set ALLOW_SHELL=true on the agent to enable full shell authority.');
    const cwd = assertExistingAllowed(String(args.cwd ?? ALLOWED_ROOTS[0]));
    const timeout = Math.min(Number(args.timeoutMs ?? 30_000), 120_000);
    const { stdout, stderr } = await execAsync(String(args.command), { cwd, timeout, maxBuffer: 2_000_000 });
    return { stdout, stderr, cwd };
  }

  throw new Error(`Unknown tool: ${tool}`);
}

async function pair(credentials: Credentials) {
  const response = await fetch(`${HTTP_BASE}/oauth/device/code`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: 'open-remote-agent',
      device_id: credentials.deviceId,
      device_name: DEVICE_NAME,
      platform: process.platform
    })
  });
  if (!response.ok) throw new Error(`Pairing request failed: HTTP ${response.status}`);
  const data: any = await response.json();

  console.log('');
  console.log('Pair this device with Open Remote MCP');
  console.log(`  Code: ${data.user_code}`);
  console.log(`  Open: ${data.verification_uri_complete}`);
  console.log('');

  while (true) {
    await new Promise(resolve => setTimeout(resolve, Math.max(1, Number(data.interval ?? 3)) * 1000));
    const tokenResponse = await fetch(`${HTTP_BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: String(data.device_code),
        client_id: 'open-remote-agent'
      })
    });
    const tokenData: any = await tokenResponse.json().catch(() => ({}));
    if (tokenResponse.ok && tokenData.access_token) {
      credentials.token = String(tokenData.access_token);
      saveCredentials(credentials);
      console.log('Device approved. Credentials stored locally.');
      return credentials;
    }
    if (tokenData.error === 'authorization_pending' || tokenData.error === 'slow_down') continue;
    throw new Error(`Pairing failed: ${tokenData.error ?? 'unknown_error'}`);
  }
}

async function ensureCredentials() {
  let credentials = loadCredentials();
  if (!credentials.token) credentials = await pair(credentials);
  saveCredentials(credentials);
  return credentials;
}

async function connect(credentials: Credentials) {
  const url = new URL(SERVER);
  url.searchParams.set('deviceId', credentials.deviceId);
  url.searchParams.set('name', DEVICE_NAME);
  url.searchParams.set('platform', process.platform);

  const ws = new WebSocket(url, {
    headers: { Authorization: `Bearer ${credentials.token}` }
  });

  ws.on('open', () => {
    console.log(`Connected as ${DEVICE_NAME} (${credentials.deviceId})`);
    console.log(`Allowed roots: ${ALLOWED_ROOTS.join(', ')}`);
    console.log(`Shell: ${ALLOW_SHELL ? 'ENABLED (full local shell authority)' : 'disabled'}`);
    ws.send(JSON.stringify({
      type: 'hello',
      capabilities: CAPABILITIES,
      localRoots: ALLOWED_ROOTS,
      localShell: ALLOW_SHELL
    }));
  });

  ws.on('message', async raw => {
    let msg: any;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (msg.type !== 'invoke') return;
    try {
      const result = await invoke(String(msg.tool), msg.args ?? {});
      ws.send(JSON.stringify({ type: 'result', id: msg.id, ok: true, result }));
    } catch (error: any) {
      ws.send(JSON.stringify({ type: 'result', id: msg.id, ok: false, error: error?.message ?? String(error) }));
    }
  });

  ws.on('close', (code, reason) => {
    console.error(`Disconnected (code ${code}${reason.length ? `, ${reason.toString()}` : ''}). Reconnecting...`);
    setTimeout(() => connect(credentials), 2500);
  });
  ws.on('error', error => console.error('Agent connection error:', error.message));
}

const credentials = await ensureCredentials();
await connect(credentials);
