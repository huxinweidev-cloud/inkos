import http from 'node:http';
import net from 'node:net';
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, realpath, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const WORKER_HEADER = 'x-inkos-worker-credential';
export const HOSTED_ORIGIN = 'https://inkos.hxwhub.eu.org';
const childEntry = fileURLToPath(new URL('./child.mjs', import.meta.url));
const sleep = ms => new Promise(resolveSleep => setTimeout(resolveSleep, ms));
const hopHeaders = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

export function cleanChildEnvironment(home) {
  return { HOME: home, PATH: '/usr/local/bin:/usr/bin:/bin', TMPDIR: join(home, 'tmp'),
    LANG: 'C.UTF-8', NODE_ENV: 'production', NODE_OPTIONS: '--max-old-space-size=1536', INKOS_HOSTED: '1' };
}

function headersForProxy(headers, host) {
  const connectionTokens = String(headers.connection ?? '').toLowerCase().split(',').map(v => v.trim());
  const result = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined || hopHeaders.has(key) || connectionTokens.includes(key) || key === 'host'
      || key === 'authorization' || key === 'cookie' || key === 'forwarded' || key.startsWith('x-inkos')
      || key.startsWith('x-forwarded-') || ['x-real-ip', 'true-client-ip', 'cf-connecting-ip'].includes(key)) continue;
    result[key] = value;
  }
  result.host = host;
  return result;
}

function safeTarget(raw) {
  if (typeof raw !== 'string' || raw.length > 8192 || !raw.startsWith('/') || raw.startsWith('//') || raw.includes('#')) return null;
  const [pathname] = raw.split('?');
  let decoded = pathname;
  for (let i = 0; i < 5; i++) {
    if (/[\\\u0000-\u0020\u007f]/u.test(decoded) || decoded.startsWith('//') || decoded.split('/').some(p => p === '.' || p === '..')) return null;
    if (!decoded.includes('%')) break;
    if (i === 4) return null;
    try { decoded = decodeURIComponent(decoded); } catch { return null; }
  }
  const url = new URL(raw, 'http://localhost');
  if ([...url.searchParams.keys()].some(key => key.toLowerCase() === 'apikey')) return null;
  return { raw, pathname, decoded };
}

function json(res, status, body) {
  if (res.destroyed || res.headersSent) return;
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function boundedControlBody(req) {
  if (!/^application\/json(?:\s*;|$)/i.test(String(req.headers['content-type'] ?? ''))) throw new Error('body');
  let size = 0;
  const chunks = [];
  for await (const chunk of req) { size += chunk.length; if (size > 16384) throw new Error('body'); chunks.push(chunk); }
  const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object' || Object.keys(parsed).length) throw new Error('body');
}

async function prepareSocket(socketPath) {
  await mkdir(dirname(socketPath), { recursive: true, mode: 0o770 });
  if (await realpath(dirname(socketPath)) !== dirname(socketPath)) throw new Error('Socket directory must be canonical');
  let info;
  try { info = await lstat(socketPath); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!info.isSocket() || (process.getuid && info.uid !== process.getuid())) throw new Error('Unsafe existing Studio socket');
  const live = await new Promise(resolveLive => {
    const socket = net.createConnection(socketPath);
    socket.setTimeout(1000);
    socket.once('connect', () => { socket.destroy(); resolveLive(true); });
    socket.once('timeout', () => { socket.destroy(); resolveLive(true); });
    socket.once('error', error => resolveLive(error.code !== 'ECONNREFUSED'));
  });
  if (live) throw new Error('Studio socket already active');
  await unlink(socketPath);
}

function listen(server, address) {
  return new Promise((yes, no) => { server.once('error', no); server.listen(address, () => { server.off('error', no); yes(); }); });
}
function closeServer(server) {
  return new Promise(resolveClose => {
    if (!server.listening) return resolveClose();
    server.close(resolveClose); server.closeAllConnections();
  });
}
function killGroup(child, signal) {
  if (!child?.pid) return;
  try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}

/** Operator-owned fixed options; never populated from a browser request. */
export async function createSupervisor(options = {}) {
  const tenantId = String(options.tenantId ?? '');
  if (!/^[1-9][0-9]*$/.test(tenantId) || !Number.isSafeInteger(Number(tenantId))) throw new Error('Positive operator-owned tenantId required');
  const root = resolve(options.projectRoot ?? '/data/project');
  const home = resolve(options.home ?? '/data/home');
  const runtime = resolve(options.runtimeDir ?? '/runtime');
  const studioSocket = join(runtime, 'studio.sock');
  const relaySocket = join(runtime, 'relay.sock');
  const studioPort = options.studioPort ?? 4567;
  const relayPort = options.relayPort ?? 8080;
  const limits = { studioConcurrency: 32, relayConcurrency: 8, studioBytes: 16 * 1024 * 1024,
    relayBytes: 4 * 1024 * 1024, streamMs: 15 * 60_000, startMs: 15_000, stopMs: 500, ...options.limits };
  for (const [name, value] of Object.entries(limits)) if (!Number.isSafeInteger(value) || value < 1 || value > 16 * 1024 * 1024) throw new Error(`Invalid limit: ${name}`);
  for (const port of [studioPort, relayPort]) if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid worker port');
  if (studioPort === relayPort) throw new Error('Ports must differ');
  await mkdir(root, { recursive: true, mode: 0o700 });
  await mkdir(join(home, 'tmp'), { recursive: true, mode: 0o700 });
  if (await realpath(root) !== root || await realpath(home) !== home) throw new Error('Project and HOME must be canonical');
  await prepareSocket(studioSocket);
  let child = null, credential = null, running = false, closing = false;
  let serial = Promise.resolve(), controlPending = 0;
  let studioActive = 0, relayActive = 0;
  const active = new Set();

  function abortRequests() { for (const abort of active) abort(); }
  async function stopChild() {
    const current = child;
    running = false; credential = null;
    abortRequests();
    if (!current) return;
    // Always kill the whole process group, even if its leader already exited.
    killGroup(current, 'SIGTERM');
    await sleep(limits.stopMs);
    killGroup(current, 'SIGKILL');
    if (current.exitCode === null && current.signalCode === null) {
      await Promise.race([new Promise(resolveExit => current.once('exit', resolveExit)), sleep(1000)]);
    }
    if (child === current) child = null;
  }
  function enqueue(operation) {
    const result = serial.then(operation);
    serial = result.catch(() => {});
    return result;
  }
  async function startChild() {
    if (closing) throw new Error('Closing');
    if (running && child) return;
    await stopChild();
    credential = randomBytes(32).toString('base64url');
    const entry = options.childEntry ?? childEntry;
    const execArgv = options.disablePermissionsForTest === true ? [] : ['--permission', '--disable-sigusr1',
      `--allow-fs-read=${options.applicationRoot ?? '/app'}`, `--allow-fs-read=${dirname(entry)}`,
      `--allow-fs-read=${root}`, `--allow-fs-read=${home}`, `--allow-fs-write=${root}`, `--allow-fs-write=${home}`];
    // Node >=25 gates networking too; Node 22 relies on network_mode:none.
    if (execArgv.length && process.allowedNodeEnvironmentFlags.has('--allow-net')) execArgv.push('--allow-net');
    const current = fork(entry, [], { cwd: root, env: cleanChildEnvironment(home),
      execPath: process.execPath, execArgv, detached: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    child = current;
    current.once('exit', () => {
      if (child === current) { running = false; credential = null; abortRequests(); }
      // Clean any surviving background processes on crashes too.
      try { killGroup(current, 'SIGKILL'); } catch { /* shutdown already owns cleanup */ }
    });
    try {
      await new Promise((yes, no) => {
        const timer = setTimeout(() => done(new Error('Child startup deadline')), limits.startMs);
        function done(error) { clearTimeout(timer); current.off('message', message); current.off('exit', exited); current.off('error', failed); error ? no(error) : yes(); }
        function message(value) { if (value?.type === 'ready') done(); else if (value?.type === 'failed') done(new Error('Child startup failed')); }
        function exited() { done(new Error('Child exited')); }
        function failed() { done(new Error('Child failed')); }
        current.on('message', message); current.once('exit', exited); current.once('error', failed);
        current.send({ type: 'initialize', credential, root, port: studioPort, origin: HOSTED_ORIGIN,
          relayBase: `http://127.0.0.1:${relayPort}/v1`, staticDir: options.staticDir ?? '/app/packages/studio/dist',
          coreModule: options.coreModule ?? '/app/packages/core/dist/index.js',
          studioModule: options.studioModule ?? '/app/packages/studio/dist/api/server.js' }, error => { if (error) done(new Error('Child IPC failed')); });
      });
      if (child !== current || current.exitCode !== null || current.signalCode !== null) throw new Error('Child not alive');
      running = true;
    } catch {
      await stopChild(); throw new Error('Worker start failed');
    }
  }

  function proxy(req, res, target, relay) {
    if ((!relay && !running) || !child || !credential || closing) { req.resume(); return json(res, 503, { error: 'WORKER_STOPPED' }); }
    const count = relay ? relayActive : studioActive;
    if (count >= (relay ? limits.relayConcurrency : limits.studioConcurrency)) { req.resume(); return json(res, 429, { error: 'WORKER_BUSY' }); }
    if (relay) relayActive++; else studioActive++;
    const maxBytes = relay ? limits.relayBytes : limits.studioBytes;
    if (Number(req.headers['content-length'] ?? 0) > maxBytes) { req.resume(); if (relay) relayActive--; else studioActive--; return json(res, 413, { error: 'BODY_TOO_LARGE' }); }
    const headers = headersForProxy(req.headers, relay ? 'localhost' : `127.0.0.1:${studioPort}`);
    if (!relay) headers[WORKER_HEADER] = credential;
    const upstream = http.request(relay ? { socketPath: relaySocket, path: target.raw, method: req.method, headers, agent: false }
      : { host: '127.0.0.1', port: studioPort, path: target.raw, method: req.method, headers, agent: false });
    let size = 0, finished = false;
    const abort = () => { upstream.destroy(); if (res.headersSent) res.destroy(); else json(res, 503, { error: 'WORKER_STOPPED' }); };
    active.add(abort);
    const timer = setTimeout(() => { upstream.destroy(); if (res.headersSent) res.destroy(); else json(res, 504, { error: 'UPSTREAM_TIMEOUT' }); }, limits.streamMs);
    function cleanup() { if (finished) return; finished = true; clearTimeout(timer); active.delete(abort); if (relay) relayActive--; else studioActive--; }
    res.once('close', () => { upstream.destroy(); cleanup(); });
    req.once('aborted', () => { upstream.destroy(); cleanup(); });
    upstream.once('error', () => { if (!res.headersSent) json(res, 502, { error: 'UPSTREAM_UNAVAILABLE' }); else res.destroy(); });
    upstream.once('response', response => {
      const output = {};
      for (const [key, value] of Object.entries(response.headers)) {
        if (value !== undefined && !hopHeaders.has(key) && !key.startsWith('x-inkos')) output[key] = value;
      }
      output['cache-control'] = 'no-store';
      res.writeHead(response.statusCode ?? 502, output);
      response.once('error', () => res.destroy());
      response.pipe(res);
    });
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) { upstream.destroy(); json(res, 413, { error: 'BODY_TOO_LARGE' }); req.resume(); return; }
      if (!upstream.write(chunk)) req.pause();
    });
    upstream.on('drain', () => req.resume());
    req.once('end', () => upstream.end());
    req.once('error', () => upstream.destroy());
  }

  const studioServer = http.createServer({ maxHeaderSize: 16384 }, async (req, res) => {
    // Exact startup binding defeats cross-tenant socket symlink/misrouting.
    // Duplicate headers are denied rather than joined/normalized.
    const bindings = req.rawHeaders.filter((_, index) => index % 2 === 0 && req.rawHeaders[index].toLowerCase() === 'x-inkos-tenant-id');
    if (bindings.length !== 1 || req.headers['x-inkos-tenant-id'] !== tenantId) { req.resume(); return json(res, 403, { error: 'TENANT_MISMATCH' }); }
    const target = safeTarget(req.url);
    if (!target) { req.resume(); return json(res, 400, { error: 'INVALID_PATH' }); }
    if (/^\/_worker(?:\/|$)/i.test(target.decoded)) {
      if (target.raw !== target.decoded || !['/_worker/start', '/_worker/stop'].includes(target.raw) || req.method !== 'POST') { req.resume(); return json(res, 404, { error: 'CONTROL_NOT_FOUND' }); }
      if (closing || controlPending >= 16) { req.resume(); return json(res, 429, { error: 'WORKER_BUSY' }); }
      controlPending++;
      const bufferedBody = boundedControlBody(req).then(() => null, () => new Error('body'));
      try {
        await enqueue(async () => {
          const bodyError = await bufferedBody;
          if (bodyError) throw bodyError;
          await (target.raw.endsWith('/start') ? startChild() : stopChild());
        });
        json(res, 200, { running });
      } catch { json(res, 503, { error: 'WORKER_CONTROL_FAILED' }); }
      finally { controlPending--; }
      return;
    }
    proxy(req, res, target, false);
  });
  const relayServer = http.createServer({ maxHeaderSize: 16384 }, (req, res) => {
    const target = safeTarget(req.url);
    const routes = { '/v1/models': 'GET', '/v1/chat/completions': 'POST', '/v1/responses': 'POST' };
    if (!target || target.raw !== target.pathname || routes[target.pathname] !== req.method) { req.resume(); return json(res, 404, { error: 'RELAY_ROUTE_FORBIDDEN' }); }
    proxy(req, res, target, true);
  });
  for (const server of [studioServer, relayServer]) {
    server.maxConnections = 128; server.headersTimeout = 10000; server.requestTimeout = 30000;
    server.keepAliveTimeout = 5000; server.maxRequestsPerSocket = 100;
    server.on('upgrade', (_req, socket) => socket.destroy());
    server.on('connect', (_req, socket) => socket.destroy());
  }
  try {
    await listen(relayServer, { host: '127.0.0.1', port: relayPort });
    await listen(studioServer, studioSocket);
    await chmod(studioSocket, 0o660);
  } catch (error) { await closeServer(relayServer); await closeServer(studioServer); throw error; }
  return { studioSocket, relaySocket, studioPort, relayPort,
    status: () => ({ running, pid: child?.pid ?? null, studioActive, relayActive }),
    async close() {
      if (closing) return;
      closing = true;
      await enqueue(stopChild);
      await Promise.all([closeServer(studioServer), closeServer(relayServer)]);
      try { await unlink(studioSocket); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  // Only non-secret, operator-owned deployment settings are accepted.
  createSupervisor({ projectRoot: process.env.INKOS_PROJECT_ROOT, home: process.env.HOME,
    runtimeDir: process.env.INKOS_RUNTIME_DIR, staticDir: process.env.INKOS_STATIC_DIR,
    tenantId: process.env.INKOS_TENANT_ID }).then(worker => {
    for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => { worker.close().then(() => process.exit(0), () => process.exit(1)); });
    console.log('Inkos worker supervisor ready');
  }).catch(() => { console.error('Inkos worker supervisor failed'); process.exitCode = 1; });
}
