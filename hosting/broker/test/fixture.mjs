import http from 'node:http';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';
import { createBroker } from '../src/broker.mjs';

// Local protocol fixtures only: no real secrets, model providers or billing.
export const INKOS = 'https://inkos.test';
export const NEWAPI = 'https://dashboard.test';
export const fakeServiceKey = 'fixture-service-key-not-production-00000000';
export const token = () => randomBytes(32).toString('base64url');
const here = path.dirname(fileURLToPath(import.meta.url));
export { sleep };

export async function until(predicate, timeout = 2500) {
  const deadline = Date.now() + timeout;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('Fixture condition timed out');
    await sleep(10);
  }
}

async function listen(server, address) {
  server.listen(address);
  await once(server, 'listening');
}
async function closeServer(server) {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
async function bytes(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString();
}
function json(response, data, status = 200) {
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(data));
}

export function call(target, pathname, { method = 'GET', headers = {}, body, chunks } = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({ ...target, path: pathname, method, headers, agent: false });
    request.once('error', reject);
    request.once('response', async response => {
      try { resolve({ status: response.statusCode, headers: response.headers, text: await bytes(response) }); }
      catch (error) { reject(error); }
    });
    if (chunks) { for (const chunk of chunks) request.write(chunk); request.end(); }
    else request.end(body);
  });
}

export async function openStream(target, pathname, { method = 'GET', headers = {}, body } = {}) {
  const request = http.request({ ...target, path: pathname, method, headers, agent: false });
  const responsePromise = once(request, 'response');
  request.end(body);
  const [response] = await responsePromise;
  // Collect opaque mock chunks, intentionally not OpenAI/model results.
  const chunks = [];
  let ended = false;
  response.on('data', chunk => chunks.push(chunk));
  response.on('error', () => {});
  response.on('close', () => { ended = true; });
  await until(() => chunks.length > 0);
  return { request, response, chunks, get ended() { return ended; }, close() { response.destroy(); request.destroy(); } };
}

export async function fixture(t, { start = true, limits = {}, stopFails = false } = {}) {
  await mkdir(path.join(here, '..', '.test-tmp'), { recursive: true });
  const root = await mkdtemp(path.join(here, '..', '.test-tmp', 'f-'));
  const runtimeRoot = path.join(root, 'r');
  const workers = new Map();
  const brokers = [];
  const privateCalls = [];
  const modelCalls = [];
  const identities = new Map();
  const tickets = new Map();
  const overrides = new Map();
  const modelStreams = new Set();
  let time = Date.now();
  let authority;
  let broker;
  let target;
  let authorityDown = false;
  let expectedCloseFailure = false;

  t.after(async () => {
    for (const item of brokers) {
      try { await item.close(); } catch (error) { if (!expectedCloseFailure || error.code !== 'WORKER_STOP_FAILED') throw error; }
    }
    if (authority) await closeServer(authority);
    for (const worker of workers.values()) await closeServer(worker.server);
    await rm(root, { recursive: true, force: true });
  });

  for (const userId of [1, 2]) {
    const directory = path.join(runtimeRoot, String(userId));
    await mkdir(directory, { recursive: true });
    const worker = { userId, fixedUserId: userId, directory, controls: [], controlHeaders: [], denied: [], requests: [], streams: new Set(), running: true, generating: false, stopFails, startDelay: 0 };
    worker.server = http.createServer(async (request, response) => {
      let text;
      try { text = await bytes(request); } catch { return; }
      if (request.headers['x-inkos-tenant-id'] !== String(worker.fixedUserId)) {
        worker.denied.push({ path: request.url, headers: request.headers });
        return json(response, { success: false, code: 'WRONG_TENANT' }, 403);
      }
      if (request.url.startsWith('/_worker/')) {
        worker.controlHeaders.push(request.headers);
        const action = request.url.slice('/_worker/'.length);
        worker.controls.push(action);
        if (action === 'stop') {
          if (worker.stopFails) return json(response, { success: false }, 503);
          worker.running = false;
          worker.generating = false;
        } else if (action === 'start') {
          if (worker.startDelay) await sleep(worker.startDelay);
          worker.running = true;
        }
        return json(response, worker.controlResult ?? { running: worker.running });
      }
      worker.requests.push({ path: request.url, headers: request.headers, text });
      if (!worker.running) return json(response, { success: false }, 503);
      if (request.url === '/api/generate') worker.generating = true;
      if (request.url === '/events') {
        response.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'public, max-age=9999', 'Set-Cookie': 'worker_secret=bad' });
        worker.streams.add(response);
        const emit = () => response.write(`data: ${JSON.stringify({ mock: true, user_id: userId })}\n\n`);
        emit();
        const timer = setInterval(emit, 30);
        response.once('close', () => { clearInterval(timer); worker.streams.delete(response); });
        return;
      }
      if (request.url.includes('/preview')) {
        response.writeHead(200, { 'Content-Type': 'text/html', 'Content-Security-Policy': "sandbox allow-scripts allow-same-origin", 'X-Frame-Options': 'SAMEORIGIN' });
        return response.end('<script>/* untrusted fixture preview */</script>');
      }
      if (request.url === '/style.css') {
        response.writeHead(200, { 'Content-Type': 'text/css', 'Cache-Control': 'public, max-age=99999', 'Set-Cookie': 'worker_secret=bad', 'X-Frame-Options': 'SAMEORIGIN' });
        return response.end('/* private fixture CSS */');
      }
      json(response, { mock: true, user_id: userId, path: request.url, headers: request.headers, text });
    });
    workers.set(userId, worker);
    await listen(worker.server, path.join(directory, 'studio.sock'));
  }

  const envelope = (response, data, status = 200) => json(response, { success: true, data }, status);
  authority = http.createServer(async (request, response) => {
    const text = await bytes(request);
    if (request.url.startsWith('/api/inkos/internal/')) {
      const endpoint = request.url.split('/').at(-1);
      const body = JSON.parse(text);
      privateCalls.push({ endpoint, headers: request.headers, body });
      if (authorityDown) return json(response, { success: false, code: 'MOCK_DOWN' }, 503);
      if (request.method !== 'POST' || request.headers['x-inkos-service-key'] !== fakeServiceKey) return json(response, { success: false }, 401);
      const override = overrides.get(endpoint);
      if (override) return await override({ request, response, body, envelope, json });
      if (endpoint === 'exchange') {
        const record = tickets.get(body.ticket);
        if (!record || record.state !== body.state || record.expires <= time || body.audience !== INKOS) return json(response, { success: false }, 401);
        tickets.delete(body.ticket);
        const identity = identities.get(record.sessionId);
        if (!identity || identity.revoked) return json(response, { success: false }, 401);
        return envelope(response, { identity: identity.identity, user_id: identity.identity.user_id, token_id: identity.tokenId, expires_at: identity.expires });
      }
      const record = identities.get(body.identity?.session_id);
      if (!record || record.revoked || record.expires * 1000 <= time || JSON.stringify(body.identity) !== JSON.stringify(record.identity)) return json(response, { success: false }, 401);
      if (endpoint === 'introspect') return envelope(response, { user_id: record.identity.user_id, expires_at: record.expires, token_id: record.tokenId });
      if (endpoint === 'relay-context') return envelope(response, { user_id: record.identity.user_id, token_id: record.tokenId, api_key: record.key, models: record.models, remain_quota: record.quota });
      return json(response, { success: false }, 404);
    }
    if (request.url.startsWith('/v1/')) {
      const userId = [...identities.values()].find(value => `Bearer ${value.key}` === request.headers.authorization)?.identity.user_id;
      const body = text ? JSON.parse(text) : null;
      modelCalls.push({ path: request.url, method: request.method, headers: request.headers, text, body, userId });
      if (body?.mock_error) {
        response.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '7' });
        return response.end('{"error":{"code":"MOCK_NATIVE_LIMIT","message":"fixture limit"}}');
      }
      if (body?.stream) {
        response.writeHead(200, { 'Content-Type': 'text/event-stream' });
        modelStreams.add(response);
        const emit = () => response.write(`data: ${JSON.stringify({ mock: true, user_id: userId })}\n\n`);
        emit();
        const timer = setInterval(emit, 30);
        response.once('close', () => { clearInterval(timer); modelStreams.delete(response); });
        return;
      }
      return json(response, { mock: true, marker: 'NO_REAL_MODEL', user_id: userId, path: request.url });
    }
    json(response, { success: false }, 404);
  });
  await listen(authority, { host: '127.0.0.1', port: 0 });
  const config = {
    inkosOrigin: INKOS, newapiOrigin: NEWAPI, newapiInternalBase: `http://127.0.0.1:${authority.address().port}`,
    serviceKey: fakeServiceKey, runtimeRoot, now: () => time,
    tenants: { tenants: [...workers.values()].map(worker => ({ user_id: worker.userId, socket_dir: worker.directory })) },
    limits: { privateTimeoutMs: 500, introspectIntervalMs: 5000, headerTimeoutMs: 1000, ...limits },
  };
  async function boot() {
    broker = await createBroker(config);
    brokers.push(broker);
    const address = await broker.listen({ host: '127.0.0.1', port: 0 });
    target = { host: '127.0.0.1', port: address.port };
    return broker;
  }
  async function preflight() {
    const response = await call(target, '/integration/start');
    const cookie = response.headers['set-cookie']?.[0].split(';')[0];
    return { response, cookie, state: cookie?.split('=')[1] };
  }
  function issue(state, userId = 1) {
    const sessionId = token();
    const record = { identity: { user_id: userId, session_id: sessionId, user_auth_version: 1, session_version: 1 },
      tokenId: userId * 100, expires: Math.floor(time / 1000) + 3600, revoked: false,
      key: `sk-fixture-only-user-${userId}`, models: ['allowed-model'], quota: 1000 };
    identities.set(sessionId, record);
    const ticket = token();
    tickets.set(ticket, { state, sessionId, expires: time + 60_000 });
    return { ticket, record };
  }
  async function exchange(preflight, issued, extra = {}) {
    return await call(target, '/integration/exchange', { method: 'POST', headers: { Origin: INKOS, 'Content-Type': 'application/json', Cookie: preflight.cookie, ...extra.headers }, body: JSON.stringify({ state: preflight.state, ticket: issued.ticket, ...extra.body }) });
  }
  async function login(userId = 1) {
    const p = await preflight();
    const issued = issue(p.state, userId);
    const response = await exchange(p, issued);
    if (response.status !== 200) throw new Error(`Fixture login failed: ${response.status} ${response.text}`);
    return { ...issued, cookie: response.headers['set-cookie'].find(value => value.startsWith('__Host-inkos=')).split(';')[0], response };
  }
  const f = { config, root, runtimeRoot, workers, privateCalls, modelCalls, identities, tickets, overrides, modelStreams, boot, preflight, issue, exchange, login,
    advance(ms) { time += ms; }, setAuthorityDown(value) { authorityDown = value; },
    allowCloseFailure() { expectedCloseFailure = true; },
    get broker() { return broker; }, get target() { return target; },
    browser(pathname, login, options = {}) { return call(target, pathname, { ...options, headers: { Cookie: login?.cookie, ...options.headers } }); },
    relay(userId, pathname, options = {}) { return call({ socketPath: path.join(runtimeRoot, String(userId), 'relay.sock') }, pathname, options); },
    relayTarget(userId) { return { socketPath: path.join(runtimeRoot, String(userId), 'relay.sock') }; },
  };
  if (start) await boot();
  return f;
}
