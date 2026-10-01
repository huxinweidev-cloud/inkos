import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createStudioServer } from '../api/server.js';
import { saveStoryGraph, StoryGraphSchema } from '@actalk/inkos-core';

const TOKEN = 'synthetic-worker-test-credential';
const ORIGIN = 'https://inkos.hxwhub.eu.org';
const headers = { 'X-Inkos-Worker-Credential': TOKEN, Origin: ORIGIN };

describe('Studio earliest hosted authorization', () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'inkos-studio-auth-'));
    await saveStoryGraph(root, 'p', StoryGraphSchema.parse({ schemaVersion: 1, projectId: 'p', title: 'Fixture', variables: [],
      nodes: [{ id: 's', type: 'start', title: 'Start', choices: [{ id: 'go', text: 'Next', targetNodeId: 'e' }] },
        { id: 'e', type: 'ending', title: 'End', choices: [] }], endings: [{ id: 'g', nodeId: 'e', title: 'Good', type: 'good' }] }));
  });
  afterEach(async () => { delete process.env.INKOS_HOSTED; await rm(root, { recursive: true, force: true }); });
  const routes = ['/', '/assets/app.js', '/unknown', '/api/v1/profiles', '/api/v1/events', '/api/v1/projects/p/export/html', '/api/v1/projects/p/preview/html'];

  it('protects APIs, SSE, exports, preview, unknown and static routes added AFTER factory', async () => {
    const app = createStudioServer({} as never, root, { allowedOrigins: [ORIGIN], authorize: request => request.headers.get('X-Inkos-Worker-Credential') === TOKEN });
    app.get('/assets/app.js', c => c.text('static-marker'));
    app.get('/', c => c.html('<h1>SPA</h1>'));
    for (const path of routes) {
      for (const method of ['GET', 'POST', 'OPTIONS']) {
        const response = await app.request(path, { method, headers: { Origin: ORIGIN } });
        expect(response.status).toBe(401);
        expect(await response.json()).toEqual({ error: { code: 'STUDIO_UNAUTHORIZED', message: 'Unauthorized' } });
      }
    }
    expect((await app.request('/assets/app.js', { headers })).status).toBe(200);
    expect((await app.request('/', { headers })).status).toBe(200);
    expect((await app.request('/api/v1/profiles', { headers })).status).toBe(200);
    expect((await app.request('/unknown', { headers })).status).toBe(404);
  });

  it('uses one trusted authorization for preview, shared export renderer and opaque-origin sandbox', async () => {
    let calls = 0;
    const app = createStudioServer({} as never, root, { allowedOrigins: [ORIGIN], authorize: async request => { calls++; return request.headers.get('X-Inkos-Worker-Credential') === TOKEN; } });
    const preview = await app.request('/api/v1/projects/p/preview/html', { headers });
    expect(preview.status).toBe(200); expect(calls).toBe(1);
    expect(await preview.text()).toContain('<!doctype html>');
    expect(preview.headers.get('Content-Disposition')).toBeNull();
    expect(preview.headers.get('Content-Security-Policy')).toContain('sandbox allow-scripts');
    expect(preview.headers.get('Content-Security-Policy')).not.toContain('allow-same-origin');
    const exported = await app.request('/api/v1/projects/p/export/html', { headers });
    expect(exported.status).toBe(200); expect(calls).toBe(2);
    expect(exported.headers.get('Content-Disposition')).toContain('attachment');
  });

  it('keeps exact allowedOrigins enforcement active AFTER auth for unsafe requests and preflights', async () => {
    const app = createStudioServer({} as never, root, { allowedOrigins: [ORIGIN], authorize: request => request.headers.get('X-Inkos-Worker-Credential') === TOKEN });
    for (const origin of ['https://hxwhub.eu.org', `${ORIGIN}.evil`, 'null']) {
      for (const method of ['GET', 'POST', 'OPTIONS']) {
        const response = await app.request('/api/v1/sessions', { method, headers: { ...headers, Origin: origin } });
        expect(response.status).toBe(403); expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
      }
    }
    const preflight = await app.request('/api/v1/sessions', { method: 'OPTIONS', headers: { ...headers, 'Access-Control-Request-Method': 'POST' } });
    expect(preflight.status).toBe(204); expect(preflight.headers.get('Access-Control-Allow-Origin')).toBe(ORIGIN);
  });

  it('fails closed on callback errors without disclosing them and preserves callback-absent CLI', async () => {
    const denied = createStudioServer({} as never, root, { authorize: () => { throw new Error('synthetic-private-error'); } });
    const response = await denied.request('/api/v1/profiles');
    expect(response.status).toBe(401); expect(await response.text()).not.toContain('synthetic-private-error');
    const normal = createStudioServer({} as never, root);
    expect((await normal.request('/api/v1/profiles')).status).toBe(200);
    expect((await normal.request('/api/v1/projects/p/preview/html')).status).toBe(200);
  });

  it('hosted asset/text endpoints cannot read a symlink to credentials', async () => {
    process.env.INKOS_HOSTED = '1';
    await writeFile(join(root, 'credentials.env'), 'synthetic-sensitive-content');
    await mkdir(join(root, 'works/p/source/assets/nodes'), { recursive: true });
    await symlink(join(root, 'credentials.env'), join(root, 'works/p/source/assets/nodes/leak.png'));
    const app = createStudioServer({} as never, root, { authorize: request => request.headers.get('X-Inkos-Worker-Credential') === TOKEN });
    const response = await app.request('/api/v1/project/files/works/p/source/assets/nodes/leak.png', { headers: { 'X-Inkos-Worker-Credential': TOKEN } });
    expect(response.status).not.toBe(200); expect(await response.text()).not.toContain('synthetic-sensitive-content');
  });
});
