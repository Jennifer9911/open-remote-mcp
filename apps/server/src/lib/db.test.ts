import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from './db.js';
import { pkceChallenge } from './security.js';

test('OAuth, device pairing, policy, and audit persistence', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'open-remote-mcp-'));
  const filename = path.join(dir, 'test.sqlite');
  let store = new Store(filename);

  const client = store.registerClient({ clientName: 'Test', redirectUris: ['https://client.example/callback'] });
  assert.ok(store.getClient(client.clientId));

  const verifier = 'test-verifier-with-enough-entropy-1234567890';
  const code = store.createAuthCode({
    clientId: client.clientId,
    redirectUri: 'https://client.example/callback',
    codeChallenge: pkceChallenge(verifier),
    scope: 'mcp offline_access'
  });
  const consumed = store.consumeAuthCode(code);
  assert.equal(consumed?.clientId, client.clientId);
  assert.equal(store.consumeAuthCode(code), null);

  const tokens = store.issueUserTokens(client.clientId, 'mcp offline_access');
  assert.equal(store.validateAccessToken(tokens.accessToken)?.clientId, client.clientId);
  const refreshed = store.refreshUserToken(tokens.refreshToken, client.clientId);
  assert.ok(refreshed?.accessToken);
  assert.equal(store.refreshUserToken(tokens.refreshToken, client.clientId), null);

  const pair = store.createDeviceCode({ deviceId: 'device-1', deviceName: 'Test Mac', platform: 'darwin' });
  assert.equal(store.exchangeDeviceCode(pair.deviceCode).status, 'pending');
  assert.equal(store.approveDeviceCode(pair.userCode), true);
  const exchange = store.exchangeDeviceCode(pair.deviceCode);
  assert.equal(exchange.status, 'approved');
  if (exchange.status !== 'approved') throw new Error('device exchange failed');
  assert.equal(store.validateDeviceToken('device-1', exchange.token), true);

  store.updateDeviceMeta({ id: 'device-1', name: 'Test Mac', platform: 'darwin', capabilities: ['read_file', 'write_file'], localRoots: ['/tmp'], localShell: false });
  assert.equal(store.setDevicePolicy('device-1', ['read_file']), true);
  assert.deepEqual(store.getDevice('device-1')?.allowed_tools, ['read_file']);

  store.audit({ id: 'audit-1', at: new Date().toISOString(), deviceId: 'device-1', tool: 'read_file', ok: true, ms: 12, summary: 'Completed' });
  assert.equal(store.listActivity(10)[0]?.id, 'audit-1');

  store.db.close();
  store = new Store(filename);
  assert.equal(store.validateAccessToken(tokens.accessToken)?.clientId, client.clientId);
  assert.equal(store.validateDeviceToken('device-1', exchange.token), true);
  assert.deepEqual(store.getDevice('device-1')?.allowed_tools, ['read_file']);
  assert.equal(store.listActivity(10)[0]?.id, 'audit-1');

  assert.equal(store.revokeDevice('device-1'), true);
  assert.equal(store.validateDeviceToken('device-1', exchange.token), false);

  store.db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});
