import test from 'node:test';
import assert from 'node:assert/strict';
import { createBroker } from '../src/broker.mjs';
import { fixture, call, openStream, until, sleep, INKOS, NEWAPI, token } from './fixture.mjs';

const post = body => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

// Every HTTP payload below is a fixture, not a model/billing success claim.
test('startup stops previous children and anonymous UI/static/export is denied', async t => {
  const f = await fixture(t);
  assert.deepEqual(f.broker.stats(), { states: 0, sessions: 0, tenants: 2, relayActive: 0, workerActive: 0 });
  for (const worker of f.workers.values()) { assert.equal(worker.running, false); assert.deepEqual(worker.controls, ['stop']); }
  for (const p of ['/', '/api/profiles', '/style.css', '/exports/book.html', '/events']) {
    const r = await call(f.target, p); assert.equal(r.status, 401); assert.equal(r.headers['cache-control'], 'no-store');
  }
});

test('handshake uses exact parent origin/source/type and secure host-only state cookie', async t => {
  const f = await fixture(t);
  const { response: r, cookie, state } = await f.preflight();
  assert.equal(r.status, 200); assert.match(state, /^[\w-]{43}$/);
  assert.match(r.headers['set-cookie'][0], /^__Host-inkos-preflight=[\w-]{43}; Path=\/; Max-Age=60; Secure; HttpOnly; SameSite=Strict$/);
  assert(!r.headers['set-cookie'][0].includes('Domain='));
  assert(r.text.includes('event.origin!==expectedOrigin||event.source!==parent'));
  assert(r.text.includes("data.type!=='inkos-ticket'||data.state!==state"));
  assert(r.text.includes(`expectedOrigin=${JSON.stringify(NEWAPI)}`));
  assert(r.text.includes("location.replace('/')")); assert(!r.text.includes('location.search'));
  assert.match(r.headers['content-security-policy'], /frame-ancestors https:\/\/dashboard\.test/);
  assert(!r.headers['access-control-allow-origin']); assert(!r.headers['x-frame-options']);
  assert(cookie.startsWith('__Host-inkos-preflight='));
});

test('exchange strictly verifies same Origin, cookie/state, JSON and one-use state', async t => {
  const f = await fixture(t);
  const p = await f.preflight(); const issued = f.issue(p.state);
  for (const origin of [undefined, NEWAPI, 'https://brother.inkos.test']) {
    const headers = { 'Content-Type': 'application/json', Cookie: p.cookie };
    if (origin) headers.Origin = origin;
    const r = await call(f.target, '/integration/exchange', { method: 'POST', headers, body: JSON.stringify({ state: p.state, ticket: issued.ticket }) });
    assert.equal(r.status, 403);
  }
  assert.equal((await f.exchange(p, issued, { headers: { Cookie: 'unrelated=fixture' } })).status, 403);
  assert.equal((await f.exchange(p, issued, { body: { state: token() } })).status, 403);
  assert.equal((await f.exchange(p, issued, { body: { user_id: 2 } })).status, 400);
  assert.equal(f.privateCalls.length, 0);
  const [a, b] = await Promise.all([f.exchange(p, issued), f.exchange(p, issued)]);
  assert.deepEqual([a.status, b.status].sort(), [200, 403]);
  const good = a.status === 200 ? a : b;
  assert.equal(good.text, '{"success":true}'); assert(!good.text.includes(issued.ticket));
  assert.match(good.headers['set-cookie'][0], /^__Host-inkos=[\w-]{43}; Path=\/; Max-Age=\d+; Secure; HttpOnly; SameSite=Strict$/);
  assert.notEqual(good.headers['set-cookie'][0].split('=')[1].split(';')[0], p.state);
  assert.match(good.headers['set-cookie'][1], /Max-Age=0/);
  assert.deepEqual(f.privateCalls[0].body, { ticket: issued.ticket, state: p.state, audience: INKOS });
  assert.equal((await f.exchange(p, issued)).status, 403);
});

test('expired broker state and expired upstream ticket fail closed; upstream consumed ticket cannot replay', async t => {
  const f = await fixture(t);
  let p = await f.preflight(); let issued = f.issue(p.state);
  f.advance(60_001); assert.equal((await f.exchange(p, issued)).status, 403);
  p = await f.preflight(); issued = f.issue(p.state);
  f.tickets.get(issued.ticket).expires = 0;
  assert.equal((await f.exchange(p, issued)).status, 401);
  assert.equal((await f.exchange(p, issued)).status, 403);
  p = await f.preflight(); issued = f.issue(p.state);
  assert.equal((await f.exchange(p, issued)).status, 200);
  const next = await f.preflight();
  assert.equal((await f.exchange(next, issued)).status, 401);
});

test('protocol envelope and original identity must exactly match; legacy fields rejected', async t => {
  const f = await fixture(t);
  for (const bad of [
    { identity: { user_id: 1, session_ref: 'legacy', user_auth_version: 1, session_version: 1 }, user_id: 1, expires_at: 9999999999, token_id: 100 },
    { identity: { user_id: 2, session_id: 's', user_auth_version: 1, session_version: 1 }, user_id: 1, expires_at: 9999999999, token_id: 100 },
    { identity: { user_id: 1, session_id: 's', user_auth_version: 1, session_version: 1, extra: true }, user_id: 1, expires_at: 9999999999, token_id: 100 },
  ]) {
    f.overrides.set('exchange', ({ response, envelope }) => envelope(response, bad));
    const p = await f.preflight(); const issued = f.issue(p.state);
    assert.equal((await f.exchange(p, issued)).status, 401);
  }
  f.overrides.set('exchange', ({ response, json }) => json(response, { success: true, identity: { user_id: 1 } }));
  const p = await f.preflight(); assert.equal((await f.exchange(p, f.issue(p.state))).status, 401);
  assert.equal(f.broker.stats().sessions, 0);
});

test('two users remain socket-isolated, all requests recheck original identity, client route hints ignored', async t => {
  const f = await fixture(t); const one = await f.login(1); const two = await f.login(2);
  for (const [login, id] of [[one, 1], [two, 2]]) {
    for (const p of ['/', '/api/profiles?user_id=2&port=9999&root=/elsewhere', '/exports/same-name.html']) {
      const r = await f.browser(p, login);
      assert.equal(r.status, 200); assert.equal(JSON.parse(r.text).user_id, id);
    }
  }
  const introspects = f.privateCalls.filter(v => v.endpoint === 'introspect');
  assert.equal(introspects.length, 6);
  assert.deepEqual(introspects[0].body, { identity: one.record.identity });
  assert.deepEqual(introspects[3].body, { identity: two.record.identity });
});

test('safe and unsafe method origin rules include CSRF, strict content types and no CORS', async t => {
  const f = await fixture(t); const login = await f.login();
  for (const headers of [{}, { Origin: NEWAPI }, { Origin: 'null' }]) {
    const r = await f.browser('/api/generate', login, { ...post({}), headers: { ...post({}).headers, ...headers } });
    assert.equal(r.status, 403); assert(!r.headers['access-control-allow-origin']);
  }
  assert.equal((await f.browser('/', login, { headers: { Origin: NEWAPI } })).status, 403);
  assert.equal((await f.browser('/api/generate', login, { method: 'POST', headers: { Origin: INKOS, 'Content-Type': 'text/plain' }, body: '{}' })).status, 415);
  assert.equal((await f.browser('/api/generate', login, { ...post({}), headers: { Origin: INKOS, 'Content-Type': 'application/json' } })).status, 200);
  assert.equal((await f.browser('/upload', login, { method: 'POST', headers: { Origin: INKOS, 'Content-Type': 'multipart/form-data; boundary=fixture' }, body: '--fixture--\r\n' })).status, 200);
  assert.equal((await f.browser('/upload', login, { method: 'OPTIONS' })).status, 405);
});

test('incoming secrets, cookies, custom and forwarding headers never enter worker; CSS is no-store', async t => {
  const f = await fixture(t); const login = await f.login();
  const r = await f.browser('/style.css', login, { headers: { Authorization: 'Bearer FAKE_CLIENT_KEY', 'X-Inkos-Service-Key': 'FAKE_PRIVATE', 'X-Inkos-Worker-Key': 'FAKE_WORKER', 'X-Forwarded-For': '1.2.3.4', Forwarded: 'for=1.2.3.4', 'X-Real-IP': '1.2.3.4', 'CF-Connecting-IP': '1.2.3.4', 'X-Custom': 'secret', 'Accept-Language': 'zh-CN' } });
  assert.equal(r.status, 200); assert.equal(r.headers['cache-control'], 'no-store');
  assert.equal(r.headers['referrer-policy'], 'no-referrer'); assert(!r.headers['set-cookie']); assert(!r.headers['x-frame-options']);
  const headers = f.workers.get(1).requests[0].headers;
  for (const field of ['authorization', 'cookie', 'x-inkos-service-key', 'x-inkos-worker-key', 'x-forwarded-for', 'forwarded', 'x-real-ip', 'cf-connecting-ip', 'x-custom']) assert(!headers[field], field);
  assert.equal(headers.origin, INKOS); assert.equal(headers.host, 'localhost'); assert.equal(headers['accept-language'], 'zh-CN');
});

test('control and traversal aliases, API key query and URL ticket are rejected before worker', async t => {
  const f = await fixture(t); const login = await f.login();
  for (const p of ['/_worker/start', '/_worker/stop', '/%5fworker/start', '/%255fworker/stop', '/integration/internal/exchange', '/integration/%69nternal/a', '/%2e%2e/_worker/start', '/a/%252e%252e/b', '/a%2f_worker/start', '/a%5cb', '/a%00b', '/integration/start?ticket=DO_NOT_ACCEPT', '/api/a?apiKey=BAD', '/api/a?%2561piKey=BAD']) {
    const r = await f.browser(p, login); assert([400, 403].includes(r.status), `${p}: ${r.status}`);
  }
  assert.equal(f.workers.get(1).requests.length, 0);
});

test('HTML preview has sandbox without allow-same-origin and exact dashboard frame ancestor', async t => {
  const f = await fixture(t); const login = await f.login(); const r = await f.browser('/books/example/preview', login);
  assert.equal(r.status, 200); assert.match(r.headers['content-security-policy'], /sandbox allow-scripts/);
  assert(!r.headers['content-security-policy'].includes('allow-same-origin'));
  assert(r.headers['content-security-policy'].includes(`frame-ancestors ${NEWAPI}`));
  assert(!r.headers['x-frame-options']);
});

test('revoke aborts Studio SSE/model SSE, stops generation and does not stop another tenant', async t => {
  const f = await fixture(t); const one = await f.login(1); const two = await f.login(2);
  await f.browser('/api/generate', one, { ...post({}), headers: { Origin: INKOS, 'Content-Type': 'application/json' } });
  await f.browser('/', two);
  const studio = await openStream(f.target, '/events', { headers: { Cookie: one.cookie } });
  const model = await openStream(f.relayTarget(1), '/v1/chat/completions', post({ model: 'allowed-model', stream: true }));
  t.after(() => { studio.close(); model.close(); });
  assert.equal(f.workers.get(1).generating, true);
  one.record.revoked = true; await f.broker.sweep();
  await until(() => studio.ended && model.ended && f.workers.get(1).streams.size === 0 && f.modelStreams.size === 0);
  assert.equal(f.workers.get(1).running, false); assert.equal(f.workers.get(1).generating, false);
  assert.equal(f.workers.get(2).running, true); assert.equal((await f.browser('/', two)).status, 200);
  assert.equal((await f.browser('/', one)).status, 401); assert.equal((await f.relay(1, '/v1/models')).status, 401);
});

test('a valid second original session keeps tenant alive; the last revocation halts it', async t => {
  const f = await fixture(t); const first = await f.login(); const second = await f.login();
  await f.browser('/', first); first.record.revoked = true; await f.broker.sweep();
  assert.equal(f.workers.get(1).running, true); assert.equal((await f.relay(1, '/v1/models')).status, 200);
  second.record.revoked = true; await f.broker.sweep(); assert.equal(f.workers.get(1).running, false);
});

test('session expiry and authority outage invalidate instead of reusing cached authorization', async t => {
  const f = await fixture(t); const login = await f.login(); await f.browser('/', login);
  f.setAuthorityDown(true); assert.equal((await f.browser('/style.css', login)).status, 401);
  await f.broker.sweep(); assert.equal(f.workers.get(1).running, false); assert.equal(f.broker.stats().sessions, 0);
  f.setAuthorityDown(false); const expired = await f.login(); f.advance(3600_001);
  assert.equal((await f.browser('/', expired)).status, 401); await f.broker.sweep(); assert.equal(f.broker.stats().sessions, 0);
});

test('automatic periodic checks revoke idle tenant generation without browser requests', async t => {
  const f = await fixture(t, { limits: { introspectIntervalMs: 150, privateTimeoutMs: 80 } });
  const login = await f.login(); await f.browser('/api/generate', login, { ...post({}), headers: { Origin: INKOS, 'Content-Type': 'application/json' } });
  login.record.revoked = true;
  await until(() => !f.workers.get(1).running && !f.workers.get(1).generating);
  assert.equal(f.broker.stats().sessions, 0);
});

test('relay is own socket/fixed path/fixed upstream and preserves native body/errors without billing edits', async t => {
  const f = await fixture(t); await f.login(1); await f.login(2);
  for (const id of [1, 2]) {
    const body = { model: 'allowed-model', input: 'fixture only', max_output_tokens: 4, user_id: 3 - id, base_url: 'http://169.254.169.254', multiplier: 0.3 };
    const r = await f.relay(id, '/v1/responses', { ...post(body), headers: { ...post(body).headers, Authorization: 'Bearer FAKE_CLIENT', Cookie: 'evil=bad', 'X-Inkos-Service-Key': 'BAD', Forwarded: 'BAD' } });
    assert.equal(r.status, 200); assert.equal(JSON.parse(r.text).user_id, id);
    const forwarded = f.modelCalls.at(-1); assert.equal(forwarded.path, '/v1/responses'); assert.equal(forwarded.userId, id); assert.equal(forwarded.text, JSON.stringify(body));
    assert.equal(forwarded.headers.authorization, `Bearer sk-fixture-only-user-${id}`);
    for (const field of ['cookie', 'x-inkos-service-key', 'forwarded']) assert(!forwarded.headers[field]);
  }
  const r = await f.relay(1, '/v1/chat/completions', post({ model: 'allowed-model', mock_error: true }));
  assert.equal(r.status, 429); assert.equal(r.headers['retry-after'], '7');
  assert.equal(r.text, '{"error":{"code":"MOCK_NATIVE_LIMIT","message":"fixture limit"}}');
  assert.equal((await f.relay(1, '/v1/models')).status, 200);
  assert(!r.text.includes('sk-fixture'));
});

test('relay denies unknown model/method/path/query and sessions cannot cross Unix sockets', async t => {
  const f = await fixture(t); await f.login(1);
  assert.equal((await f.relay(2, '/v1/models')).status, 401);
  for (const body of [{ model: 'other' }, {}, { model: ['allowed-model'] }]) assert.equal((await f.relay(1, '/v1/chat/completions', post(body))).status, 403);
  for (const p of ['/v1/models?q=x', '/v1/chat/completions?url=http://elsewhere', '/v1/%6dodels', '/v1/completions', '/_worker/start']) assert.equal((await f.relay(1, p, post({ model: 'allowed-model' }))).status, 403);
  assert.equal((await f.relay(1, '/v1/models', post({}))).status, 403);
  assert.equal(f.modelCalls.length, 0);
});

test('relay context requires exact ready sk- key, models string allowlist and finite positive quota', async t => {
  const f = await fixture(t); const login = await f.login();
  const base = { user_id: 1, token_id: 100, api_key: login.record.key, models: ['allowed-model'], remain_quota: 100 };
  for (const change of [{ api_key: 'raw-token' }, { api_key: 'sk-sk-invalid-double-prefix' }, { models: {} }, { models: [] }, { models: [{ id: 'allowed-model' }] }, { models: ['allowed-model', 'allowed-model'] }, { remain_quota: 0 }, { user_id: 2 }]) {
    f.overrides.set('relay-context', ({ response, envelope }) => envelope(response, { ...base, ...change }));
    assert.equal((await f.relay(1, '/v1/chat/completions', post({ model: 'allowed-model' }))).status, 403, JSON.stringify(change));
  }
  assert.equal(f.modelCalls.length, 0);
});

test('token rebind and removed model abort current relay streams but do not fabricate errors', async t => {
  const f = await fixture(t); const login = await f.login();
  const stream = await openStream(f.relayTarget(1), '/v1/responses', post({ model: 'allowed-model', stream: true }));
  t.after(() => stream.close()); login.record.tokenId++;
  await f.broker.sweep(); await until(() => stream.ended && f.modelStreams.size === 0);
  const second = await openStream(f.relayTarget(1), '/v1/responses', post({ model: 'allowed-model', stream: true }));
  t.after(() => second.close()); login.record.models = ['different-model'];
  await f.broker.sweep(); await until(() => second.ended && f.modelStreams.size === 0);
});

test('client disconnect cancels Studio and relay streams and releases concurrency', async t => {
  const f = await fixture(t); const login = await f.login();
  const studio = await openStream(f.target, '/events', { headers: { Cookie: login.cookie } });
  const model = await openStream(f.relayTarget(1), '/v1/responses', post({ model: 'allowed-model', stream: true }));
  studio.close(); model.close();
  await until(() => f.workers.get(1).streams.size === 0 && f.modelStreams.size === 0 && f.broker.stats().relayActive === 0 && f.broker.stats().workerActive === 0);
});

test('relay and worker concurrency is bounded and released after cancellation', async t => {
  const f = await fixture(t, { limits: { relayConcurrency: 1, workerConcurrency: 1 } }); const login = await f.login();
  const studio = await openStream(f.target, '/events', { headers: { Cookie: login.cookie } });
  const model = await openStream(f.relayTarget(1), '/v1/responses', post({ model: 'allowed-model', stream: true }));
  t.after(() => { studio.close(); model.close(); });
  assert.equal((await f.browser('/', login)).status, 429);
  assert.equal((await f.relay(1, '/v1/models')).status, 429);
  studio.close(); model.close(); await until(() => !f.broker.stats().workerActive && !f.broker.stats().relayActive);
  assert.equal((await f.browser('/', login)).status, 200); assert.equal((await f.relay(1, '/v1/models')).status, 200);
});

test('known-length and chunked relay/worker body overflow return clean bounded 413', async t => {
  const f = await fixture(t, { limits: { relayBodyBytes: 128, workerBodyBytes: 128 } }); const login = await f.login();
  for (const chunked of [false, true]) {
    const body = JSON.stringify({ model: 'allowed-model', input: 'x'.repeat(300) });
    const options = { method: 'POST', headers: { 'Content-Type': 'application/json', ...(chunked ? {} : { 'Content-Length': Buffer.byteLength(body) }) }, ...(chunked ? { chunks: [body.slice(0, 100), body.slice(100)] } : { body }) };
    assert.equal((await f.relay(1, '/v1/responses', options)).status, 413);
    assert.equal((await f.browser('/api/generate', login, { ...options, headers: { ...options.headers, Origin: INKOS } })).status, 413);
  }
  assert.equal(f.modelCalls.length, 0);
});

test('rotation invalidates old app cookie and old operations, no session fixation', async t => {
  const f = await fixture(t); const login = await f.login();
  const stream = await openStream(f.target, '/events', { headers: { Cookie: login.cookie } }); t.after(() => stream.close());
  const p = await f.preflight(); const issued = f.issue(p.state);
  const response = await f.exchange(p, issued, { headers: { Cookie: `${p.cookie}; ${login.cookie}` } });
  assert.equal(response.status, 200); await until(() => stream.ended);
  assert.equal((await f.browser('/', login)).status, 401); assert.equal(f.broker.stats().sessions, 1);
});

test('restart logs everyone out, stops children and recreates fixed Unix relays', async t => {
  const f = await fixture(t); const old = await f.login(); await f.browser('/api/generate', old, { ...post({}), headers: { Origin: INKOS, 'Content-Type': 'application/json' } });
  await f.broker.close(); assert.equal(f.workers.get(1).running, false); await f.boot();
  assert.equal((await f.browser('/', old)).status, 401); assert.equal((await f.relay(1, '/v1/models')).status, 401);
  const fresh = await f.login(); assert.equal((await f.browser('/', fresh)).status, 200);
});

test('worker supervisor recreation is recovered by next authenticated start', async t => {
  const f = await fixture(t); const login = await f.login(); assert.equal((await f.browser('/', login)).status, 200);
  f.workers.get(1).running = false; assert.equal((await f.browser('/', login)).status, 200);
  assert.equal(f.workers.get(1).controls.filter(value => value === 'start').length, 2);
});

test('unsafe origins/duplicate tenants/directory aliases and >10s checks fail config validation', async t => {
  const f = await fixture(t, { start: false });
  for (const change of [
    { inkosOrigin: 'http://inkos.test' }, { inkosOrigin: `${INKOS}/` }, { newapiOrigin: INKOS }, { newapiInternalBase: 'http://user:pass@127.0.0.1' },
    { newapiInternalBase: 'http://127.0.0.1/v1' }, { serviceKey: '' },
    { tenants: { tenants: [f.config.tenants.tenants[0], f.config.tenants.tenants[0]] } },
    { tenants: { tenants: [{ user_id: 1, socket_dir: f.workers.get(2).directory }] } },
    { tenants: { tenants: [{ user_id: '1', socket_dir: f.workers.get(1).directory }] } },
    { limits: { introspectIntervalMs: 10_001 } },
  ]) await assert.rejects(createBroker({ ...f.config, ...change }));
});

test('broker refuses serving if startup cannot halt previously running workers', async t => {
  const f = await fixture(t, { start: false, stopFails: true });
  await assert.rejects(f.boot(), /WORKER_UNAVAILABLE/);
});

test('shutdown cannot admit an exchange already waiting on authority', async t => {
  const f = await fixture(t); const p = await f.preflight(); const issued = f.issue(p.state);
  let release; let entered = false;
  f.overrides.set('exchange', async ({ response, envelope }) => {
    entered = true; await new Promise(resolve => { release = resolve; });
    envelope(response, { identity: issued.record.identity, user_id: 1, token_id: 100, expires_at: issued.record.expires });
  });
  const exchanging = f.exchange(p, issued).catch(() => null);
  await until(() => entered);
  const closing = f.broker.close(); release(); const result = await exchanging; await closing;
  assert.notEqual(result?.status, 200); assert.equal(f.broker.stats().sessions, 0);
});

test('parallel admitted UI requests coalesce start instead of a linear control backlog', async t => {
  const f = await fixture(t); const login = await f.login(); f.workers.get(1).startDelay = 40;
  const results = await Promise.all(Array.from({ length: 8 }, () => f.browser('/', login)));
  assert(results.every(result => result.status === 200));
  assert.equal(f.workers.get(1).controls.filter(value => value === 'start').length, 1);
});
