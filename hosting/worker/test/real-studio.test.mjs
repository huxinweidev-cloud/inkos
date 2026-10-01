import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createSupervisor, HOSTED_ORIGIN } from '../src/supervisor.mjs';
const source = process.env.INKOS_SOURCE_ROOT;
const scratch = process.env.TMPDIR ?? '/home/ubuntu/.hermes/cache/scratch';
async function freePort() { const server = http.createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port; }
function request(address, path, options = {}) {
  return new Promise((yes, no) => {
    const req = http.request({ ...(typeof address === 'string' ? { socketPath: address } : { host: '127.0.0.1', port: address }),
      path, method: options.method ?? 'GET', headers: options.headers ?? {}, agent: false }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.once('error', no);
      res.once('end', () => yes({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    }); req.setTimeout(20000, () => req.destroy(new Error('Smoke deadline'))); req.once('error', no); req.end(options.body);
  });
}

test('REAL compiled Studio + production IPC child: authorized static/API/preview, direct denial, persisted Work through restart', { skip: !source }, async t => {
  const base = await mkdtemp(join(scratch, 'inkos-real-worker-'));
  const runtime = join(base, 'runtime'); await mkdir(runtime);
  const worker = await createSupervisor({ tenantId: 17, projectRoot: join(base, 'project'), home: join(base, 'home'), runtimeDir: runtime,
    applicationRoot: source, studioModule: join(source, 'packages/studio/dist/api/server.js'), staticDir: join(source, 'packages/studio/dist'),
    studioPort: await freePort(), relayPort: await freePort(), limits: { startMs: 20000, stopMs: 50 } });
  const relay = http.createServer((req, res) => {
    if (req.url !== '/v1/models') throw new Error('Smoke must not call a model');
    res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ data: [{ id: 'synthetic-broker-model' }] }));
  });
  await new Promise(resolve => relay.listen(worker.relaySocket, resolve));
  t.after(async () => { await worker.close(); await new Promise(resolve => relay.close(resolve)); await rm(base, { recursive: true, force: true }); });
  const control = action => request(worker.studioSocket, `/_worker/${action}`, { method: 'POST', headers: { 'X-Inkos-Tenant-ID': '17', 'Content-Type': 'application/json' }, body: '{}' });
  const started = await control('start'); assert.equal(started.status, 200, started.text);
  const headers = { 'X-Inkos-Tenant-ID': '17', Origin: HOSTED_ORIGIN };
  for (const path of ['/', '/api/v1/profiles', '/api/v1/sessions']) {
    const proxied = await request(worker.studioSocket, path, { headers }); assert.equal(proxied.status, 200, proxied.text.slice(0, 200));
    assert.equal((await request(worker.studioPort, path)).status, 401);
  }
  const root = join(base, 'project');
  const { saveStoryGraph, StoryGraphSchema, loadProjectConfig } = await import(new URL(`file://${source}/packages/core/dist/index.js`).href);
  const config = await loadProjectConfig(root, { consumer: 'studio' });
  assert.equal(config.llm.model, 'synthetic-broker-model'); assert.equal(config.llm.service, 'custom:newapi');
  await saveStoryGraph(root, 'fixture', StoryGraphSchema.parse({ schemaVersion: 1, projectId: 'fixture', title: 'Real Studio smoke', variables: [],
    nodes: [{ id: 's', type: 'start', title: 'Start', choices: [{ id: 'go', text: 'Next', targetNodeId: 'e' }] },
      { id: 'e', type: 'ending', title: 'End', choices: [] }], endings: [{ id: 'g', nodeId: 'e', title: 'Good', type: 'good' }] }));
  const preview = await request(worker.studioSocket, '/api/v1/projects/fixture/preview/html', { headers });
  assert.equal(preview.status, 200, preview.text); assert(preview.text.includes('<!doctype html>'));
  assert(preview.headers['content-security-policy'].includes('sandbox allow-scripts')); assert(!preview.headers['content-security-policy'].includes('allow-same-origin'));
  const exported = await request(worker.studioSocket, '/api/v1/projects/fixture/export/html', { headers }); assert.equal(exported.status, 200);
  assert(exported.headers['content-disposition'].includes('attachment'));
  assert.equal((await request(worker.studioSocket, '/api/v1/profiles', { headers: { ...headers, Origin: 'https://hxwhub.eu.org' } })).status, 403);
  const html = await request(worker.studioSocket, '/', { headers });
  const asset = html.text.match(/(?:src|href)="(\/assets\/[^\"]+)"/)[1];
  assert.equal((await request(worker.studioPort, asset)).status, 401);
  assert.equal((await request(worker.studioSocket, asset, { headers })).status, 200);
  await writeFile(join(root, 'preserved-content.md'), 'persistent fixture');
  assert.equal((await control('stop')).status, 200); assert.equal((await control('start')).status, 200);
  assert.equal(await readFile(join(root, 'preserved-content.md'), 'utf8'), 'persistent fixture');
  assert.equal((await request(worker.studioSocket, '/api/v1/projects/fixture/preview/html', { headers })).status, 200);
});
