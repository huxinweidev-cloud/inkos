import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { loadConfig } from '../src/config.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fakeKey = 'fixture-only-service-key-not-production-00000';
async function configFixture(t) {
  await mkdir(path.join(root, '.test-tmp'), { recursive: true });
  const directory = await mkdtemp(path.join(root, '.test-tmp', 'config-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const keyFile = path.join(directory, 'service-key'); const tenantFile = path.join(directory, 'tenants.json');
  await writeFile(keyFile, `${fakeKey}\n`, { mode: 0o600 });
  await writeFile(tenantFile, JSON.stringify({ tenants: [{ user_id: 1, socket_dir: '/runtime/1' }] }));
  const env = { INKOS_ORIGIN: 'https://inkos.test', NEWAPI_ORIGIN: 'https://dashboard.test', NEWAPI_INTERNAL_BASE: 'http://new-api:3000', INKOS_SERVICE_KEY_FILE: keyFile, INKOS_TENANTS_FILE: tenantFile };
  return { directory, keyFile, tenantFile, env };
}

test('fixed env configuration uses only mounted key and tenant files, runtime is fixed', async t => {
  const f = await configFixture(t);
  const config = await loadConfig({ ...f.env, INKOS_SERVICE_KEY: 'IGNORED_ENV_SECRET', INKOS_PORT: '9999', INKOS_RUNTIME_ROOT: '/elsewhere' });
  assert.equal(config.serviceKey, fakeKey); assert.equal(config.runtimeRoot, '/runtime');
  assert.equal(config.inkosOrigin, f.env.INKOS_ORIGIN); assert.equal(config.newapiInternalBase, 'http://new-api:3000');
  assert.deepEqual(config.tenants, { tenants: [{ user_id: 1, socket_dir: '/runtime/1' }] });
});

test('missing, malformed, empty, directory or oversize configuration fails closed', async t => {
  const f = await configFixture(t);
  await assert.rejects(loadConfig({ ...f.env, INKOS_SERVICE_KEY_FILE: undefined }));
  await assert.rejects(loadConfig({ ...f.env, INKOS_TENANTS_FILE: f.directory }));
  await writeFile(f.tenantFile, '{bad-json'); await assert.rejects(loadConfig(f.env));
  await writeFile(f.tenantFile, ''); await assert.rejects(loadConfig(f.env));
  await writeFile(f.tenantFile, 'x'.repeat(128 * 1024 + 1)); await assert.rejects(loadConfig(f.env));
  await writeFile(f.tenantFile, '{"tenants":[]}');
  await writeFile(f.keyFile, 'x'.repeat(1025)); await assert.rejects(loadConfig(f.env));
});

test('config files may not be symlinks including symlink path ancestors', async t => {
  const f = await configFixture(t);
  const link = path.join(f.directory, 'key-link'); await symlink(f.keyFile, link);
  await assert.rejects(loadConfig({ ...f.env, INKOS_SERVICE_KEY_FILE: link }));
  const actualDir = path.join(f.directory, 'actual'); const linkedDir = path.join(f.directory, 'linked');
  await mkdir(actualDir); await writeFile(path.join(actualDir, 'key'), fakeKey);
  await symlink(actualDir, linkedDir);
  await assert.rejects(loadConfig({ ...f.env, INKOS_SERVICE_KEY_FILE: path.join(linkedDir, 'key') }));
});

test('main fail-closed CLI exits 1 with fixed non-secret failure log', async () => {
  const child = spawn(process.execPath, ['src/main.mjs'], { cwd: root, env: { PATH: process.env.PATH }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', b => { stdout += b; }); child.stderr.on('data', b => { stderr += b; });
  const status = await new Promise((resolve, reject) => { child.on('error', reject); child.on('exit', resolve); });
  assert.equal(status, 1); assert.equal(stdout, '');
  assert.equal(stderr, 'Inkos broker startup failed; check mounted configuration and Unix socket ownership\n');
});
