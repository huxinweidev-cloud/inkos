import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './fixture.mjs';

// Emulate a TOCTOU/socket replacement: directory still belongs to tenant 1,
// but the contacted supervisor enforces the fixed tenant 2 identity.
test('server-owned tenant header is forced into Studio proxy and all worker controls', async t => {
  const f = await fixture(t); const login = await f.login(1);
  const response = await f.browser('/', login, { headers: { 'X-Inkos-Tenant-ID': '2' } });
  assert.equal(response.status, 200);
  const worker = f.workers.get(1);
  assert.equal(worker.requests[0].headers['x-inkos-tenant-id'], '1');
  for (const headers of worker.controlHeaders) assert.equal(headers['x-inkos-tenant-id'], '1');
  assert.equal(f.workers.get(2).requests.length, 0);
  login.record.revoked = true; await f.broker.sweep();
  assert.equal(worker.controlHeaders.at(-1)['x-inkos-tenant-id'], '1');
});

test('wrong socket mapping user 1 reaches supervisor 2 with header 1 and is rejected', async t => {
  const f = await fixture(t); const login = await f.login(1);
  const wrong = f.workers.get(1); wrong.fixedUserId = 2;
  const response = await f.browser('/?user_id=2', login, { headers: { 'X-Inkos-Tenant-ID': '2' } });
  assert.equal(response.status, 503);
  assert.equal(wrong.requests.length, 0);
  assert.equal(wrong.denied.at(-1).path, '/_worker/start');
  assert.equal(wrong.denied.at(-1).headers['x-inkos-tenant-id'], '1');
  wrong.fixedUserId = 1;
});
