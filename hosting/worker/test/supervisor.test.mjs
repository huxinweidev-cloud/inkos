import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import { mkdtemp, mkdir, readFile, rm, stat, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSupervisor, HOSTED_ORIGIN } from '../src/supervisor.mjs';
import { HOSTED_SERVICE, PLACEHOLDER_KEY } from '../src/bootstrap.mjs';

const fixtures = fileURLToPath(new URL('./fixtures/', import.meta.url));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function freePort() {
  const server = http.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
function request(address, path = '/', options = {}) {
  return new Promise((yes, no) => {
    const req = http.request({ ...(typeof address === 'string' ? { socketPath: address } : { host: '127.0.0.1', port: address }),
      path, method: options.method ?? 'GET', headers: options.headers ?? {}, agent: false }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.once('error', no); res.once('end', () => yes({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.setTimeout(10000, () => req.destroy(new Error('Test request deadline'))); req.once('error', no); req.end(options.body);
  });
}
const control = (worker, tenant, action) => request(worker.studioSocket, `/_worker/${action}`, {
  method: 'POST', headers: { 'X-Inkos-Tenant-ID': String(tenant), 'Content-Type': 'application/json' }, body: '{}' });
async function fixture(t, tenant = 1, extra = {}) {
  const base = await mkdtemp(join(process.env.TMPDIR ?? '/home/ubuntu/.hermes/cache/scratch', 'inkos-worker-'));
  const runtime = join(base, 'runtime'); await mkdir(runtime);
  const worker = await createSupervisor({ tenantId: tenant, projectRoot: join(base, 'project'), home: join(base, 'home'), runtimeDir: runtime,
    studioPort: await freePort(), relayPort: await freePort(), childEntry: join(fixtures, 'studio-double.mjs'),
    disablePermissionsForTest: true, limits: { stopMs: 30, startMs: 10000 }, ...extra });
  t.after(async () => { await worker.close(); await rm(base, { recursive: true, force: true }); });
  return { worker, base, runtime, tenant };
}
async function dead(pid) {
  for (let attempt = 0; attempt < 100; attempt++) {
    try { const status = await readFile(`/proc/${pid}/stat`, 'utf8'); if (status.split(') ')[1].startsWith('Z')) return true; }
    catch (error) { if (['ENOENT', 'ESRCH'].includes(error.code)) return true; throw error; }
    await sleep(10);
  }
  return false;
}

test('real Unix supervisor: fail-closed binding, serialized idempotent lifecycle, IPC-only private auth and group stop (Studio TEST DOUBLE)', async t => {
  const { worker, base } = await fixture(t);
  assert.equal((await request(worker.studioSocket, '/')).status, 403);
  assert.equal((await control(worker, 2, 'start')).status, 403);
  assert.equal((await request(worker.studioSocket, '/', { headers: { 'X-Inkos-Tenant-ID': '1' } })).status, 503);
  process.env.PARENT_SYNTHETIC_SECRET = 'synthetic-parent-secret';
  t.after(() => delete process.env.PARENT_SYNTHETIC_SECRET);
  const starts = await Promise.all(Array.from({ length: 8 }, () => control(worker, 1, 'start')));
  assert(starts.every(response => response.status === 200));
  const initial = await request(worker.studioSocket, '/', { headers: { 'X-Inkos-Tenant-ID': '1', Origin: HOSTED_ORIGIN,
    Authorization: 'Bearer client-forgery', Cookie: 'client-cookie', 'X-Inkos-Worker-Credential': 'forged', 'X-Inkos-Service-Key': 'forged', 'X-Forwarded-For': '127.0.0.1' } });
  assert.equal(initial.status, 200);
  const body = JSON.parse(initial.text);
  assert.equal(body.pid, worker.status().pid); assert.equal(body.root, join(base, 'project')); assert.equal(body.home, join(base, 'home'));
  assert.equal(body.origin, HOSTED_ORIGIN); assert.equal(body.parentSecretPresent, false);
  assert.equal(body.inEnvironment, false); assert.equal(body.inArgv, false); assert.equal(body.inProcEnvironment, false); assert.equal(body.inProcCmdline, false);
  for (const header of ['cookie', 'authorization', 'x-inkos-tenant-id', 'x-inkos-service-key', 'x-forwarded-for']) assert(!body.headers.includes(header));
  assert(body.headers.includes('x-inkos-worker-credential'));
  assert.equal((await request(worker.studioPort, '/')).status, 401);
  assert.equal((await request(worker.studioPort, '/', { headers: { 'X-Inkos-Worker-Credential': 'forged' } })).status, 401);
  assert.equal((await stat(worker.studioSocket)).mode & 0o777, 0o660);
  assert.equal((await control(worker, 1, 'start')).status, 200); assert.equal(worker.status().pid, body.pid);
  assert.equal((await control(worker, 1, 'stop')).status, 200);
  assert(await dead(body.pid)); assert(await dead(body.descendant));
  assert.equal((await control(worker, 1, 'stop')).status, 200);
  assert.equal((await control(worker, 1, 'start')).status, 200);
  const restarted = JSON.parse((await request(worker.studioSocket, '/', { headers: { 'X-Inkos-Tenant-ID': '1' } })).text);
  assert.notEqual(restarted.pid, body.pid); assert.notEqual(restarted.fingerprint, body.fingerprint);
});

test('two real sockets reject tenant-crossed routing and absolute symlink redirect for ALL routes', async t => {
  const first = await fixture(t, 1), second = await fixture(t, 2);
  assert.equal((await control(first.worker, 1, 'start')).status, 200);
  assert.equal((await control(second.worker, 2, 'start')).status, 200);
  const alias = join(first.runtime, 'misrouted.sock'); await symlink(second.worker.studioSocket, alias);
  for (const route of ['/', '/api/v1/profiles', '/_worker/start', '/_worker/stop']) {
    const response = await request(alias, route, { method: route.startsWith('/_worker') ? 'POST' : 'GET',
      headers: { 'X-Inkos-Tenant-ID': '1', 'Content-Type': 'application/json' }, body: route.startsWith('/_worker') ? '{}' : undefined });
    assert.equal(response.status, 403); assert.equal(JSON.parse(response.text).error, 'TENANT_MISMATCH');
  }
  assert(second.worker.status().running); assert(first.worker.status().running);
});

test('fixed-path localhost model relay uses Unix only, strips secrets and enforces body/concurrency bounds', async t => {
  const { worker } = await fixture(t, 1, { limits: { stopMs: 30, startMs: 10000, relayBytes: 64, relayConcurrency: 1 } });
  const calls = [];
  const relay = http.createServer((req, res) => {
    calls.push({ path: req.url, headers: req.headers });
    req.resume(); res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ data: [{ id: 'test-model' }] }));
  });
  await new Promise(resolve => relay.listen(worker.relaySocket, resolve));
  t.after(() => new Promise(resolve => relay.close(resolve)));
  assert.equal((await control(worker, 1, 'start')).status, 200);
  assert.equal((await request(worker.relayPort, '/v1/models', { headers: { Authorization: 'Bearer placeholder', Cookie: 'forged', 'X-Inkos-Tenant-ID': '2' } })).status, 200);
  assert.equal(calls[0].path, '/v1/models'); assert(!calls[0].headers.authorization); assert(!calls[0].headers.cookie); assert(!calls[0].headers['x-inkos-tenant-id']);
  for (const route of ['/_worker/start', '/v1/models?url=http://metadata', '/v1/embeddings', '/%76%31/models', 'http://example.com/v1/models']) {
    assert.equal((await request(worker.relayPort, route)).status, 404);
  }
  assert.equal((await request(worker.relayPort, '/v1/chat/completions', { method: 'POST', body: 'x'.repeat(65) })).status, 413);
  assert.equal((await request(worker.studioSocket, '/%5fworker/start', { method: 'POST', headers: { 'X-Inkos-Tenant-ID': '1' } })).status, 404);
  assert.equal((await request(worker.studioSocket, '/?apiKey=forgery', { headers: { 'X-Inkos-Tenant-ID': '1' } })).status, 400);
  assert.equal((await control(worker, 1, 'stop')).status, 200);
  assert.equal((await request(worker.relayPort, '/v1/models')).status, 503);
});

test('production IPC child/bootstrap with module TEST DOUBLE: broker models, fixed placeholder, exact origin, runtime permissions denied', async t => {
  const { worker, base } = await fixture(t, 7, { childEntry: fileURLToPath(new URL('../src/child.mjs', import.meta.url)),
    studioModule: join(fixtures, 'server-module-double.mjs'), applicationRoot: join(fixtures), disablePermissionsForTest: false });
  const relay = http.createServer((req, res) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ data: [{ id: 'broker-model-A' }, { id: 'broker-model-B' }] })); });
  await new Promise(resolve => relay.listen(worker.relaySocket, resolve));
  t.after(() => new Promise(resolve => relay.close(resolve)));
  const started = await control(worker, 7, 'start'); assert.equal(started.status, 200, started.text);
  const proxied = JSON.parse((await request(worker.studioSocket, '/', { headers: { 'X-Inkos-Tenant-ID': '7' } })).text);
  assert.equal(proxied.hostname, '127.0.0.1'); assert.deepEqual(proxied.origins, [HOSTED_ORIGIN]);
  assert.equal(proxied.runtimeReadDenied, true); assert.equal(proxied.runtimeWriteDenied, true);
  assert.equal((await request(worker.studioPort, '/')).status, 401);
  const config = JSON.parse(await readFile(join(base, 'project/inkos.json'), 'utf8'));
  assert.equal(config.llm.service, HOSTED_SERVICE); assert.equal(config.llm.baseUrl, `http://127.0.0.1:${worker.relayPort}/v1`);
  assert.deepEqual(config.llm.services[0].models, ['broker-model-A', 'broker-model-B']);
  assert.equal(config.llm.model, 'broker-model-A');
  const secrets = JSON.parse(await readFile(join(base, 'project/.inkos/secrets.json'), 'utf8'));
  assert.equal(secrets.services[HOSTED_SERVICE].apiKey, PLACEHOLDER_KEY);
});

test('stop aborts a real ongoing SSE proxy and kills background child work', async t => {
  const { worker } = await fixture(t); await control(worker, 1, 'start');
  const before = JSON.parse((await request(worker.studioSocket, '/', { headers: { 'X-Inkos-Tenant-ID': '1' } })).text);
  let stream;
  const closed = new Promise((yes, no) => {
    const req = http.get({ socketPath: worker.studioSocket, path: '/sse', headers: { 'X-Inkos-Tenant-ID': '1' }, agent: false }, response => {
      stream = response; response.once('close', yes); response.once('data', () => control(worker, 1, 'stop').catch(no));
    }); req.once('error', no);
  });
  await Promise.race([closed, sleep(5000).then(() => { throw new Error('SSE not aborted'); })]);
  assert(stream.destroyed); assert(await dead(before.pid)); assert(await dead(before.descendant));
});
