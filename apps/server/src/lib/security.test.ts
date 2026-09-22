import test from 'node:test';
import assert from 'node:assert/strict';
import { pkceChallenge, signSession, verifySession } from './security.js';

test('PKCE challenge matches RFC 7636 S256 example', () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  assert.equal(pkceChallenge(verifier), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

test('admin session signatures verify and reject tampering', () => {
  const token = signSession('test-secret', 60);
  assert.equal(verifySession(token, 'test-secret'), true);
  assert.equal(verifySession(token + 'x', 'test-secret'), false);
  assert.equal(verifySession(token, 'different-secret'), false);
});
