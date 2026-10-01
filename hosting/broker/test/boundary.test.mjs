import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import http from 'node:http';
import { rename, symlink, unlink, stat } from 'node:fs/promises';
import path from 'node:path';
import { fixture, call, openStream, until, sleep, INKOS, NEWAPI, token } from './fixture.mjs';
import { createBroker } from '../src/broker.mjs';

const post = body => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

test('handshake executable rejects wrong source/origin/type/state and ignores ticket replay', async t => {
  const f = await fixture(t); const p = await f.preflight();
  const script = p.response.text.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)[1];
  const sent = []; const fetched = []; const replaced = []; const listeners = new Map();
  const parent = { postMessage: (...args) => sent.push(args) };
  const sandbox = { parent, window: {}, document: { body: {} }, location: { replace: x => replaced.push(x) }, addEventListener: (kind, handler) => listeners.set(kind, handler), fetch: async (...args) => { fetched.push(args); return { ok: true }; } };
  vm.runInNewContext(script, sandbox);
  assert.deepEqual(JSON.parse(JSON.stringify(sent)), [[{ type: 'inkos-ready', state: p.state }, NEWAPI]]);
  const handler = listeners.get('message'); const data = { type: 'inkos-ticket', state: p.state, ticket: token() };
  for (const message of [
    { origin: INKOS, source: parent, data }, { origin: NEWAPI, source: {}, data },
    { origin: NEWAPI, source: parent, data: { ...data, type: 'other' } },
    { origin: NEWAPI, source: parent, data: { ...data, state: token() } },
    { origin: NEWAPI, source: parent, data: { ...data, ticket: 'not-a-ticket' } },
  ]) await handler(message);
  assert.equal(fetched.length, 0);
  await handler({ origin: NEWAPI, source: parent, data });
  await handler({ origin: NEWAPI, source: parent, data });
  assert.equal(fetched.length, 1); assert.equal(fetched[0][0], '/integration/exchange');
  assert.deepEqual(JSON.parse(fetched[0][1].body), { ticket: data.ticket, state: p.state });
  assert.deepEqual(replaced, ['/']);
});

test('actual wrong socket mapping sends server tenant 1 to supervisor 2 and denies control', async t => {
  const f = await fixture(t); const login = await f.login(1);
  const one = path.join(f.workers.get(1).directory, 'studio.sock');
  const two = path.join(f.workers.get(2).directory, 'studio.sock');
  const saved = `${one}.saved`;
  await rename(one, saved); await rename(two, one);
  try {
    const r = await f.browser('/', login, { headers: { 'X-Inkos-Tenant-ID': '2' } });
    assert.equal(r.status, 503); assert.equal(f.workers.get(2).requests.length, 0);
    const denied = f.workers.get(2).denied.at(-1);
    assert.equal(denied.path, '/_worker/start'); assert.equal(denied.headers['x-inkos-tenant-id'], '1');
  } finally { await rename(one, two); await rename(saved, one); }
});

test('proxy itself is denied by fixed tenant 2 after socket swap between start and proxy', async t => {
  const f = await fixture(t); const login = await f.login(1);
  const worker = f.workers.get(1); const one = path.join(worker.directory, 'studio.sock');
  const two = path.join(f.workers.get(2).directory, 'studio.sock'); const saved = `${one}.saved`;
  const original = worker.server.listeners('request')[0];
  worker.server.removeListener('request', original);
  let swapped = false;
  worker.server.on('request', async (request, response) => {
    if (request.url === '/_worker/start') {
      await rename(one, saved); await rename(two, one); swapped = true;
    }
    await original(request, response);
  });
  try {
    const r = await f.browser('/exports/same-name.html', login, { headers: { 'X-Inkos-Tenant-ID': '2' } });
    assert.equal(r.status, 403);
    const denied = f.workers.get(2).denied.at(-1);
    assert.equal(denied.path, '/exports/same-name.html'); assert.equal(denied.headers['x-inkos-tenant-id'], '1');
    assert.equal(f.workers.get(2).requests.length, 0);
  } finally { if (swapped) { await rename(one, two); await rename(saved, one); } }
});

test('symlink studio socket is denied without relying on lstat as the tenant identity barrier', async t => {
  const f = await fixture(t); const login = await f.login(1);
  const one = path.join(f.workers.get(1).directory, 'studio.sock'); const saved = `${one}.saved`;
  await rename(one, saved); await symlink(path.join(f.workers.get(2).directory, 'studio.sock'), one);
  try {
    const r = await f.browser('/', login);
    assert.equal(r.status, 503); assert.equal(f.workers.get(2).denied.length, 0);
  } finally { await unlink(one); await rename(saved, one); }
});

test('private authority timeout/malformed response never authenticates or discloses secrets', async t => {
  const f = await fixture(t, { limits: { privateTimeoutMs: 80 } }); const login = await f.login();
  f.overrides.set('introspect', async ({ response, envelope }) => { await sleep(150); envelope(response, { user_id: 1, expires_at: login.record.expires, token_id: 100 }); });
  const r = await f.browser('/api/profiles', login);
  assert.equal(r.status, 503); assert.equal(JSON.parse(r.text).code, 'AUTHORITY_UNAVAILABLE');
  assert(!r.text.includes('fixture-service')); assert.equal(f.broker.stats().sessions, 0);
  f.overrides.delete('introspect'); const next = await f.login();
  f.overrides.set('introspect', ({ response }) => { response.end('not-json'); });
  assert.equal((await f.browser('/', next)).status, 503); assert.equal(f.broker.stats().sessions, 0);
});

test('preflight/session capacities are bounded and preflight capacity frees on expiry', async t => {
  const f = await fixture(t, { limits: { maxStates: 2, maxSessions: 1, maxSessionsPerTenant: 1 } });
  await f.preflight(); await f.preflight(); assert.equal((await call(f.target, '/integration/start')).status, 429);
  f.advance(60_001); const login = await f.login();
  const p = await f.preflight(); const issued = f.issue(p.state, 2); assert.equal((await f.exchange(p, issued)).status, 429);
  assert.equal(f.broker.stats().sessions, 1); assert.equal((await f.browser('/', login)).status, 200);
});

test('duplicate cookie and malformed exchange types fail before private authority', async t => {
  const f = await fixture(t); const p = await f.preflight(); const issued = f.issue(p.state);
  assert.equal((await f.exchange(p, issued, { headers: { Cookie: `${p.cookie}; ${p.cookie}` } })).status, 400);
  assert.equal((await f.exchange(p, issued, { body: { ticket: [issued.ticket] } })).status, 400);
  assert.equal(f.privateCalls.length, 0);
});

test('configured check interval includes bounded sweep time and never permits >10s revoke budget', async t => {
  const f = await fixture(t, { start: false });
  await assert.rejects(async () => {
    const unexpected = await createBroker({ ...f.config, limits: { introspectIntervalMs: 9000, privateTimeoutMs: 3000 } });
    await unexpected.close();
  }, /Unsafe broker limits/);
});

test('failed revocation stop is retried, and close reports stop failure rather than success', async t => {
  const f = await fixture(t); const login = await f.login(); await f.browser('/', login);
  const worker = f.workers.get(1); worker.stopFails = true; login.record.revoked = true;
  await f.broker.sweep(); assert.equal(worker.running, true);
  worker.stopFails = false; await f.broker.sweep(); assert.equal(worker.running, false);
  worker.stopFails = true; f.allowCloseFailure();
  try { await assert.rejects(f.broker.close(), /WORKER_STOP_FAILED/); }
  finally { worker.stopFails = false; }
});

test('live relay socket cannot be stolen; permissions are 0600', async t => {
  const f = await fixture(t);
  for (const id of [1, 2]) assert.equal((await stat(path.join(f.workers.get(id).directory, 'relay.sock'))).mode & 0o777, 0o600);
  await assert.rejects(createBroker(f.config), /Relay socket already in use/);
  assert.equal((await f.relay(1, '/v1/models')).status, 401);
});

test('CONNECT and WebSocket upgrades are rejected rather than becoming a generic proxy', async t => {
  const f = await fixture(t);
  const connect = await new Promise((resolve, reject) => {
    const request = http.request({ ...f.target, method: 'CONNECT', path: '169.254.169.254:80', agent: false });
    request.on('error', reject);
    request.on('connect', (response, socket) => { socket.destroy(); resolve(response.statusCode); });
    request.end();
  });
  assert.equal(connect, 405);
  assert.equal((await call(f.target, '/', { headers: { Connection: 'Upgrade', Upgrade: 'websocket' } })).status, 405);
});

test('cold worker start has separate timeout budget from private auth and stop checks', async t => {
  const f = await fixture(t, { limits: { privateTimeoutMs: 80 } }); const login = await f.login();
  f.workers.get(1).startDelay = 160;
  assert.equal((await f.browser('/', login)).status, 200);
});

test('worker start must report running=true, not merely HTTP 200', async t => {
  const f = await fixture(t); const login = await f.login();
  const worker = f.workers.get(1); worker.controlResult = { running: false };
  assert.equal((await f.browser('/', login)).status, 503);
  assert.equal(worker.requests.length, 0); delete worker.controlResult;
});

test('last-session revoke cancels hanging cold-start request before stop control', async t => {
  const f = await fixture(t, { limits: { workerStartTimeoutMs: 5000 } }); const login = await f.login();
  const worker = f.workers.get(1); const original = worker.server.listeners('request')[0];
  worker.server.removeListener('request', original); let entered = false;
  worker.server.on('request', (request, response) => {
    if (request.url === '/_worker/start') { entered = true; request.resume(); return; }
    void original(request, response);
  });
  const pending = f.browser('/', login).catch(() => null); await until(() => entered);
  login.record.revoked = true; await f.broker.sweep(); const response = await pending;
  assert.notEqual(response?.status, 200); assert.equal(worker.running, false); assert.equal(f.broker.stats().sessions, 0);
});

test('expired original sessions abort both active streams and stop generation', async t => {
  const f = await fixture(t); const login = await f.login();
  await f.browser('/api/generate', login, { ...post({}), headers: { Origin: INKOS, 'Content-Type': 'application/json' } });
  const studio = await openStream(f.target, '/events', { headers: { Cookie: login.cookie } });
  const relay = await openStream(f.relayTarget(1), '/v1/responses', post({ model: 'allowed-model', stream: true }));
  t.after(() => { studio.close(); relay.close(); });
  f.advance(3600_001); await f.broker.sweep(); await until(() => studio.ended && relay.ended);
  assert.equal(f.workers.get(1).running, false); assert.equal(f.workers.get(1).generating, false);
});

test('production default limits validate without relying on test overrides', async t => {
  const f = await fixture(t, { start: false }); const broker = await createBroker({ ...f.config, limits: undefined });
  try { assert.equal(broker.stats().sessions, 0); } finally { await broker.close(); }
});
