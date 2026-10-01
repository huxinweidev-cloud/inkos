import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { lstat, realpath, chmod, unlink } from 'node:fs/promises';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const APP_COOKIE = '__Host-inkos';
const PREFLIGHT_COOKIE = '__Host-inkos-preflight';
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
const SAFE = new Set(['GET', 'HEAD']);
const REQUEST_HEADERS = new Set(['accept', 'accept-language', 'content-type', 'content-length', 'range', 'if-range', 'last-event-id']);
const RESPONSE_HEADERS = new Set(['content-type', 'content-length', 'content-disposition', 'content-encoding', 'content-range', 'accept-ranges', 'etag', 'last-modified', 'retry-after']);
const DEFAULTS = Object.freeze({
  maxTenants: 128, maxStates: 1024, maxSessions: 1024, maxSessionsPerTenant: 32,
  preflightMs: 60_000, sessionMs: 8 * 60 * 60 * 1000, introspectIntervalMs: 5000,
  privateTimeoutMs: 2000, workerStartTimeoutMs: 20_000, headerTimeoutMs: 15_000, privateResponseBytes: 64 * 1024,
  relayBodyBytes: 1024 * 1024, workerBodyBytes: 32 * 1024 * 1024,
  relayConcurrency: 4, relayGlobalConcurrency: 64, workerConcurrency: 16, workerGlobalConcurrency: 256,
});

class Rejection extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
const reject = (status, code) => { throw new Rejection(status, code); };
const randomToken = () => randomBytes(32).toString('base64url');
const positiveInteger = n => Number.isSafeInteger(n) && n > 0;
const object = v => !!v && typeof v === 'object' && !Array.isArray(v);
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const epochMs = value => Number.isSafeInteger(value) && value > 0 ? value * 1000 : NaN;

function origin(value, name, internal = false) {
  let url;
  try { url = new URL(value); } catch { throw new Error(`Invalid ${name}`); }
  if ((!internal && url.protocol !== 'https:') || (internal && !['http:', 'https:'].includes(url.protocol)) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash || value !== url.origin) {
    throw new Error(`Invalid ${name}`);
  }
  return url;
}

function validateLimits(overrides = {}) {
  const limits = { ...DEFAULTS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!(name in DEFAULTS) || !positiveInteger(value)) throw new Error(`Invalid limit: ${name}`);
  }
  if (limits.introspectIntervalMs + 2 * limits.privateTimeoutMs > 10_000 || limits.privateTimeoutMs >= limits.introspectIntervalMs ||
      limits.preflightMs > 60_000 || limits.sessionMs > DEFAULTS.sessionMs ||
      limits.maxTenants > 512 || limits.maxStates > 8192 || limits.maxSessions > 8192 ||
      limits.maxSessionsPerTenant > 128 || limits.workerStartTimeoutMs > 30_000 || limits.privateResponseBytes > 1024 * 1024 ||
      limits.relayBodyBytes > 16 * 1024 * 1024 || limits.workerBodyBytes > 64 * 1024 * 1024 ||
      limits.workerGlobalConcurrency > 1024 || limits.relayGlobalConcurrency > 256) throw new Error('Unsafe broker limits');
  return Object.freeze(limits);
}

async function tenantMap(config, runtimeRoot, maxTenants) {
  if (!object(config) || Object.keys(config).length !== 1 || !Array.isArray(config.tenants) ||
      config.tenants.length === 0 || config.tenants.length > maxTenants) throw new Error('Invalid tenant mapping');
  const root = await realpath(runtimeRoot);
  if (root !== path.resolve(runtimeRoot)) throw new Error('Runtime root must not be a symlink');
  const tenants = new Map();
  const directories = new Set();
  for (const item of config.tenants) {
    if (!object(item) || Object.keys(item).sort().join(',') !== 'socket_dir,user_id' || !positiveInteger(item.user_id) ||
        typeof item.socket_dir !== 'string' || item.socket_dir !== path.join(root, String(item.user_id)) ||
        tenants.has(item.user_id) || directories.has(item.socket_dir)) throw new Error('Invalid or duplicate tenant mapping');
    const stat = await lstat(item.socket_dir);
    if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(item.socket_dir) !== item.socket_dir ||
        (process.getuid && stat.uid !== process.getuid())) throw new Error('Unsafe tenant socket directory');
    directories.add(item.socket_dir);
    tenants.set(item.user_id, {
      userId: item.user_id, directory: item.socket_dir, studioSocket: path.join(item.socket_dir, 'studio.sock'),
      relaySocket: path.join(item.socket_dir, 'relay.sock'), sessions: new Set(), operations: new Set(),
      relayActive: 0, workerActive: 0, started: false, stopped: false, control: Promise.resolve(), pendingStart: null, pendingStop: null, startRequest: null, relayServer: null,
    });
  }
  return tenants;
}

function cookies(request) {
  const map = new Map();
  const text = request.headers.cookie;
  if (text === undefined) return map;
  if (typeof text !== 'string' || text.length > 8192) reject(400, 'INVALID_COOKIE');
  for (const piece of text.split(';')) {
    const separator = piece.indexOf('=');
    if (separator <= 0) reject(400, 'INVALID_COOKIE');
    const name = piece.slice(0, separator).trim();
    const value = piece.slice(separator + 1).trim();
    if (map.has(name)) reject(400, 'DUPLICATE_COOKIE');
    map.set(name, value);
  }
  return map;
}

function cookie(name, value, seconds) {
  return `${name}=${value}; Path=/; Max-Age=${seconds}; Secure; HttpOnly; SameSite=Strict`;
}

function inspectPath(raw) {
  if (typeof raw !== 'string' || raw.length > 8192 || !raw.startsWith('/') || raw.startsWith('//') || raw.includes('#')) reject(400, 'INVALID_PATH');
  const [pathname] = raw.split('?');
  let decoded = pathname;
  for (let i = 0; i < 4; i++) {
    if (/[\\\u0000-\u001f\u007f]/u.test(decoded) || decoded.startsWith('//') || decoded.split('/').some(s => s === '.' || s === '..')) reject(400, 'INVALID_PATH');
    if (/^\/(?:_worker(?:\/|$)|integration\/internal(?:\/|$))/i.test(decoded)) reject(403, 'CONTROL_FORBIDDEN');
    if (!decoded.includes('%')) break;
    let next;
    try { next = decodeURIComponent(decoded); } catch { reject(400, 'INVALID_PATH'); }
    if (next === decoded) break;
    decoded = next;
    if (i === 3 || /%2f|%5c/i.test(pathname)) reject(400, 'ENCODED_PATH_FORBIDDEN');
  }
  if (decoded.includes('%')) reject(400, 'INVALID_PATH');
  const parsed = new URL(raw, 'http://local.invalid');
  for (const key of parsed.searchParams.keys()) {
    let value = key;
    for (let i = 0; i < 4 && value.includes('%'); i++) {
      try { value = decodeURIComponent(value); } catch { reject(400, 'INVALID_QUERY'); }
    }
    if (value.toLowerCase() === 'apikey') reject(403, 'API_KEY_QUERY_FORBIDDEN');
  }
  return { pathname: decoded, rawPathname: pathname, search: parsed.search };
}

function requireOrigin(request, expected) {
  const provided = request.headers.origin;
  if ((!SAFE.has(request.method) || provided !== undefined) && provided !== expected) reject(403, 'ORIGIN_FORBIDDEN');
}

function requireMedia(request) {
  const type = request.headers['content-type'] || '';
  if (!/^application\/json(?:\s*;|$)/i.test(type) && !/^multipart\/form-data\s*;\s*boundary=/i.test(type)) reject(415, 'CONTENT_TYPE_FORBIDDEN');
}

async function readBytes(stream, maxBytes) {
  const length = stream.headers?.['content-length'];
  if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > maxBytes)) reject(413, 'BODY_TOO_LARGE');
  const chunks = [];
  let size = 0;
  for await (const chunk of stream.iterator({ destroyOnReturn: false })) {
    size += chunk.length;
    if (size > maxBytes) reject(413, 'BODY_TOO_LARGE');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

async function readJson(request, maxBytes) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] || '')) reject(415, 'JSON_REQUIRED');
  const bytes = await readBytes(request, maxBytes);
  try {
    const body = JSON.parse(bytes.toString('utf8'));
    if (!object(body)) reject(400, 'INVALID_JSON');
    return { body, bytes };
  } catch (error) { if (error instanceof Rejection) throw error; reject(400, 'INVALID_JSON'); }
}

function validIdentity(identity, userId) {
  return object(identity) && Object.keys(identity).sort().join(',') === 'session_id,session_version,user_auth_version,user_id' &&
    identity.user_id === userId && positiveInteger(userId) && typeof identity.session_id === 'string' &&
    identity.session_id.length > 0 && identity.session_id.length <= 256 &&
    Number.isSafeInteger(identity.user_auth_version) && identity.user_auth_version >= 0 &&
    Number.isSafeInteger(identity.session_version) && identity.session_version >= 0;
}

function filteredHeaders(incoming, allowed) {
  const headers = {};
  for (const [key, value] of Object.entries(incoming)) if (allowed.has(key) && value !== undefined) headers[key] = value;
  return headers;
}

async function requireStudioSocket(tenant) {
  let stat;
  try { stat = await lstat(tenant.studioSocket); } catch { reject(503, 'WORKER_UNAVAILABLE'); }
  if (!stat.isSocket() || stat.isSymbolicLink() || (process.getuid && stat.uid !== process.getuid())) reject(503, 'WORKER_UNAVAILABLE');
  // A later pathname replacement remains possible: the supervisor must ALSO
  // authenticate the fixed numeric X-Inkos-Tenant-ID on every Unix request.
}

async function removeStaleSocket(socketPath) {
  let stat;
  try { stat = await lstat(socketPath); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!stat.isSocket() || (process.getuid && stat.uid !== process.getuid())) throw new Error('Unsafe existing relay socket');
  const live = await new Promise(resolve => {
    const socket = net.createConnection(socketPath);
    socket.setTimeout(1000);
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('timeout', () => { socket.destroy(); resolve(true); });
    socket.once('error', error => { socket.destroy(); resolve(!['ECONNREFUSED', 'ENOENT'].includes(error.code)); });
  });
  if (live) throw new Error('Relay socket already in use');
  await unlink(socketPath);
}

/** No credentials are logged. Create isolated Unix relays and an unbound HTTP server. */
export async function createBroker(options) {
  if (!object(options)) throw new Error('Broker configuration required');
  const inkos = origin(options.inkosOrigin, 'INKOS_ORIGIN');
  const newapi = origin(options.newapiOrigin, 'NEWAPI_ORIGIN');
  const internal = origin(options.newapiInternalBase, 'NEWAPI_INTERNAL_BASE', true);
  if (inkos.origin === newapi.origin) throw new Error('Integration requires separate exact origins');
  if (typeof options.serviceKey !== 'string' || options.serviceKey.length < 32 || options.serviceKey.length > 512 || /[\s\x00-\x1f\x7f]/.test(options.serviceKey)) throw new Error('Invalid service key');
  const limits = validateLimits(options.limits);
  const tenants = await tenantMap(options.tenants, options.runtimeRoot || '/runtime', limits.maxTenants);
  const now = options.now || Date.now;
  const sessions = new Map();
  const states = new Map();
  const transport = internal.protocol === 'https:' ? https : http;
  const privateAgent = new transport.Agent({ keepAlive: true, maxSockets: limits.maxSessions + 32, maxFreeSockets: 8 });
  const modelAgent = new transport.Agent({ keepAlive: true, maxSockets: limits.relayGlobalConcurrency, maxFreeSockets: 8 });
  let closed = false;
  let closePromise;
  let sweepPromise;
  let relayActive = 0;
  let workerActive = 0;
  let timer;

  function security(response, nonce, preview = false) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Security-Policy', nonce
      ? `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors ${newapi.origin}`
      : preview
        ? `sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors ${newapi.origin}`
        : `frame-ancestors ${newapi.origin}; object-src 'none'; base-uri 'self'`);
    response.removeHeader('X-Frame-Options');
  }
  function failure(response, error) {
    if (response.destroyed) return;
    if (response.headersSent) { response.destroy(); return; }
    security(response);
    // Rejected uploads are not drained/reused; end the response cleanly.
    response.setHeader('Connection', 'close');
    response.statusCode = error instanceof Rejection ? error.status : 502;
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.end(JSON.stringify({ success: false, code: error instanceof Rejection ? error.code : 'UPSTREAM_UNAVAILABLE' }));
  }
  function pruneStates() {
    const timestamp = now();
    for (const [state, expires] of states) if (expires <= timestamp) states.delete(state);
  }

  async function privateCall(endpoint, payload) {
    if (closed) reject(503, 'BROKER_CLOSED');
    const bytes = Buffer.from(JSON.stringify(payload));
    if (bytes.length > 16 * 1024) reject(400, 'PRIVATE_BODY_TOO_LARGE');
    return await new Promise((resolve, rejectPromise) => {
      const request = transport.request(new URL(`/api/inkos/internal/${endpoint}`, internal), {
        method: 'POST', agent: privateAgent,
        headers: { 'Content-Type': 'application/json', 'Content-Length': bytes.length, 'X-Inkos-Service-Key': options.serviceKey },
      });
      const deadline = setTimeout(() => request.destroy(new Error('Private deadline')), limits.privateTimeoutMs);
      deadline.unref();
      request.on('error', () => { clearTimeout(deadline); rejectPromise(new Rejection(503, 'AUTHORITY_UNAVAILABLE')); });
      request.on('response', async response => {
        try {
          const result = await readBytes(response, limits.privateResponseBytes);
          if (response.statusCode < 200 || response.statusCode >= 300) reject(401, 'AUTHORITY_DENIED');
          let envelope;
          try { envelope = JSON.parse(result.toString('utf8')); } catch { reject(503, 'INVALID_AUTHORITY_RESPONSE'); }
          if (!object(envelope) || envelope.success !== true || !object(envelope.data)) reject(401, 'AUTHORITY_DENIED');
          resolve(envelope.data);
        } catch (error) { response.destroy(); request.destroy(); rejectPromise(error); }
        finally { clearTimeout(deadline); }
      });
      request.end(bytes);
    });
  }

  function control(tenant, action) {
    // A cold child start has a longer budget, but must not hold a last-session
    // revocation/close stop behind its HTTP request for that whole budget.
    if (action === 'stop' && tenant.sessions.size === 0) tenant.startRequest?.destroy();
    const pending = action === 'start' ? 'pendingStart' : 'pendingStop';
    if (tenant[pending]) return tenant[pending];
    const task = tenant.control.catch(() => {}).then(async () => {
      if (action === 'stop' && tenant.sessions.size > 0) return;
      if (action === 'start' && (closed || tenant.sessions.size === 0)) reject(401, 'SESSION_REVOKED');
      await requireStudioSocket(tenant);
      if (action === 'start' && (closed || tenant.sessions.size === 0)) reject(401, 'SESSION_REVOKED');
      await new Promise((resolve, rejectPromise) => {
        const request = http.request({ socketPath: tenant.studioSocket, method: 'POST', path: `/_worker/${action}`, agent: false,
          headers: { 'Content-Type': 'application/json', 'Content-Length': 2, 'X-Inkos-Tenant-ID': String(tenant.userId) } });
        if (action === 'start') {
          tenant.startRequest = request;
          request.once('close', () => { if (tenant.startRequest === request) tenant.startRequest = null; });
        }
        const deadline = setTimeout(() => request.destroy(), action === 'start' ? limits.workerStartTimeoutMs : limits.privateTimeoutMs);
        deadline.unref();
        request.on('error', () => { clearTimeout(deadline); rejectPromise(new Rejection(503, 'WORKER_UNAVAILABLE')); });
        request.on('response', async response => {
          try {
            const bytes = await readBytes(response, 16 * 1024);
            if (response.statusCode < 200 || response.statusCode >= 300) reject(503, 'WORKER_UNAVAILABLE');
            let readiness;
            try { readiness = JSON.parse(bytes.toString('utf8')); } catch { reject(503, 'WORKER_UNAVAILABLE'); }
            if (!object(readiness) || readiness.running !== (action === 'start')) reject(503, 'WORKER_UNAVAILABLE');
            tenant.started = action === 'start';
            tenant.stopped = action === 'stop';
            resolve();
          } catch (error) { request.destroy(); rejectPromise(error); }
          finally { clearTimeout(deadline); }
        });
        request.end('{}');
      });
    });
    tenant.control = task;
    tenant[pending] = task;
    const clear = () => { if (tenant[pending] === task) tenant[pending] = null; };
    task.then(clear, clear);
    return task;
  }

  function invalidate(session) {
    if (sessions.get(session.cookie) !== session) return;
    sessions.delete(session.cookie);
    session.tenant.sessions.delete(session);
    for (const operation of [...session.operations]) operation.abort();
    if (session.tenant.sessions.size === 0) {
      for (const operation of [...session.tenant.operations]) operation.abort();
      session.tenant.started = false;
      session.tenant.stopped = false;
      void control(session.tenant, 'stop').catch(() => {});
    }
  }

  async function live(session) {
    if (!session || sessions.get(session.cookie) !== session || session.expires <= now()) {
      if (session) invalidate(session);
      reject(401, 'SESSION_REQUIRED');
    }
    try {
      const data = await privateCall('introspect', { identity: session.identity });
      if (data.user_id !== session.userId || !positiveInteger(data.token_id) || !Number.isFinite(epochMs(data.expires_at)) || epochMs(data.expires_at) <= now()) reject(401, 'SESSION_REVOKED');
      if (sessions.get(session.cookie) !== session) reject(401, 'SESSION_REVOKED');
      session.expires = Math.min(session.expires, epochMs(data.expires_at));
      session.tokenId = data.token_id;
      return data;
    } catch (error) { invalidate(session); throw error; }
  }

  async function relayContext(session) {
    const data = await privateCall('relay-context', { identity: session.identity });
    if (data.user_id !== session.userId || !positiveInteger(data.token_id) ||
        typeof data.api_key !== 'string' || !/^sk-(?!sk-)[^\s\x00-\x1f\x7f]{1,508}$/.test(data.api_key) ||
        !Array.isArray(data.models) || data.models.length === 0 || data.models.length > 1024 ||
        data.models.some(model => typeof model !== 'string' || !model || model.length > 256) ||
        new Set(data.models).size !== data.models.length || !Number.isSafeInteger(data.remain_quota) || data.remain_quota <= 0 ||
        sessions.get(session.cookie) !== session) reject(403, 'RELAY_CONTEXT_DENIED');
    return data;
  }

  function register(session, response) {
    let aborted = false;
    const disposables = new Set();
    const operation = {
      session, contextToken: null, model: null,
      attach(resource) { disposables.add(resource); if (aborted) resource.destroy(); },
      abort() {
        if (aborted) return;
        aborted = true;
        for (const resource of disposables) resource.destroy();
        response.destroy();
        operation.finish();
      },
      finish() {
        session.operations.delete(operation);
        session.tenant.operations.delete(operation);
        response.removeListener('close', operation.abort);
      },
    };
    session.operations.add(operation);
    session.tenant.operations.add(operation);
    response.once('close', operation.abort);
    return operation;
  }

  async function sweep() {
    if (closed) return;
    if (sweepPromise) return await sweepPromise;
    sweepPromise = (async () => {
      pruneStates();
      await Promise.all([...sessions.values()].map(session => live(session).catch(() => {})));
      // After the bounded session check, controls and relay-context checks
      // run concurrently. A hung stop may not postpone stream revocation.
      const stopping = Promise.all([...tenants.values()].map(async tenant => {
        if (tenant.sessions.size === 0 && !tenant.stopped) await control(tenant, 'stop').catch(() => {});
      }));
      // Re-check active model grants too: token disable/rebind/model removal must cut streams.
      const active = [...tenants.values()].flatMap(tenant => [...tenant.operations].filter(op => op.contextToken !== null));
      const checkingModels = Promise.all(active.map(async operation => {
        try {
          const context = await relayContext(operation.session);
          if (context.token_id !== operation.contextToken || (operation.model && !context.models.includes(operation.model))) operation.abort();
        } catch { operation.abort(); }
      }));
      await Promise.all([stopping, checkingModels]);
    })();
    try { await sweepPromise; } finally { sweepPromise = undefined; }
  }

  async function proxy(request, response, session) {
    const tenant = session.tenant;
    if (tenant.workerActive >= limits.workerConcurrency || workerActive >= limits.workerGlobalConcurrency) reject(429, 'WORKER_BUSY');
    tenant.workerActive++;
    workerActive++;
    let operation;
    try {
      // Supervisor start is idempotent; always send it so supervisor recreation is recoverable.
      await control(tenant, 'start');
      if (sessions.get(session.cookie) !== session || response.destroyed) reject(401, 'SESSION_REVOKED');
      const knownLength = request.headers['content-length'];
      if (knownLength !== undefined && (!/^\d+$/.test(knownLength) || Number(knownLength) > limits.workerBodyBytes)) reject(413, 'BODY_TOO_LARGE');
      operation = register(session, response);
      const headers = filteredHeaders(request.headers, REQUEST_HEADERS);
      headers.origin = inkos.origin;
      headers['x-inkos-tenant-id'] = String(session.userId);
      headers.host = 'localhost';
      await requireStudioSocket(tenant);
      const upstream = http.request({ socketPath: tenant.studioSocket, method: request.method, path: request.url, headers, agent: false });
      operation.attach(upstream);
      let size = 0;
      const bounded = new Transform({ transform(chunk, encoding, callback) {
        size += chunk.length;
        callback(size > limits.workerBodyBytes ? new Rejection(413, 'BODY_TOO_LARGE') : null, chunk);
      } });
      operation.attach(bounded);
      const deadline = setTimeout(() => upstream.destroy(new Rejection(504, 'WORKER_TIMEOUT')), limits.headerTimeoutMs);
      deadline.unref();
      const completed = new Promise((resolve, rejectPromise) => {
        upstream.once('error', rejectPromise);
        upstream.once('response', async incoming => {
          clearTimeout(deadline);
          operation.attach(incoming);
          try {
            response.writeHead(incoming.statusCode, filteredHeaders(incoming.headers, RESPONSE_HEADERS));
            // Real stream pipeline: bounded buffering and backpressure, no SSE parsing/re-serialization.
            await pipeline(incoming, response);
            resolve();
          } catch (error) { rejectPromise(error); }
        });
      });
      // Do not put IncomingMessage into pipeline: pipeline destroys the
      // browser socket on overflow before a clean 413 can be delivered.
      const onUploadError = error => bounded.destroy(error);
      request.once('error', onUploadError);
      const upload = pipeline(bounded, upstream);
      request.pipe(bounded);
      try { await Promise.all([completed, upload]); }
      finally {
        clearTimeout(deadline);
        request.unpipe(bounded);
        request.removeListener('error', onUploadError);
        upstream.destroy();
        bounded.destroy();
      }
    } finally {
      operation?.finish();
      tenant.workerActive--;
      workerActive--;
    }
  }

  async function browser(request, response) {
    security(response);
    if (closed) reject(503, 'BROKER_CLOSED');
    if (!METHODS.has(request.method)) reject(405, 'METHOD_FORBIDDEN');
    const info = inspectPath(request.url);
    if (info.pathname.startsWith('/integration')) {
      if (info.rawPathname !== info.pathname || info.search) reject(400, 'INVALID_INTEGRATION_PATH');
      if (request.method === 'GET' && info.pathname === '/integration/start') {
        // The start document is navigated by an iframe, never fetched using sibling-origin CORS.
        if (request.headers.origin !== undefined && ![inkos.origin, newapi.origin].includes(request.headers.origin)) reject(403, 'ORIGIN_FORBIDDEN');
        pruneStates();
        if (states.size >= limits.maxStates) reject(429, 'PREFLIGHT_BUSY');
        const state = randomToken();
        states.set(state, now() + limits.preflightMs);
        const nonce = randomToken();
        security(response, nonce);
        response.setHeader('Set-Cookie', cookie(PREFLIGHT_COOKIE, state, Math.floor(limits.preflightMs / 1000)));
        response.setHeader('Content-Type', 'text/html; charset=utf-8');
        response.end(`<!doctype html><meta charset="utf-8"><title>Inkos sign-in</title><script nonce="${nonce}">\n'use strict';\nconst state=${JSON.stringify(state)}, expectedOrigin=${JSON.stringify(newapi.origin)};\nlet exchanging=false;\naddEventListener('message',async event=>{\n if(event.origin!==expectedOrigin||event.source!==parent||exchanging)return;\n const data=event.data;\n if(!data||data.type!=='inkos-ticket'||data.state!==state||typeof data.ticket!=='string'||!${TOKEN}.test(data.ticket))return;\n exchanging=true;\n try{const response=await fetch('/integration/exchange',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ticket:data.ticket,state})});if(response.ok)location.replace('/');else document.body.textContent='Sign-in denied. Reopen Inkos from the dashboard.';}catch{document.body.textContent='Sign-in unavailable.';}\n});\nif(parent!==window)parent.postMessage({type:'inkos-ready',state},expectedOrigin);\n</script><body>Connecting to Inkos…</body>`);
        return;
      }
      if (request.method === 'POST' && info.pathname === '/integration/exchange') {
        requireOrigin(request, inkos.origin);
        const { body } = await readJson(request, 16 * 1024);
        if (Object.keys(body).sort().join(',') !== 'state,ticket' || typeof body.state !== 'string' || typeof body.ticket !== 'string' || !TOKEN.test(body.state) || !TOKEN.test(body.ticket)) reject(400, 'INVALID_EXCHANGE');
        const preflight = cookies(request).get(PREFLIGHT_COOKIE);
        if (!TOKEN.test(preflight || '') || !equal(preflight, body.state) || !states.has(body.state) || states.get(body.state) <= now()) reject(403, 'PREFLIGHT_REQUIRED');
        states.delete(body.state); // Consume before the private exchange: no concurrent/retry replay.
        response.setHeader('Set-Cookie', cookie(PREFLIGHT_COOKIE, '', 0));
        const data = await privateCall('exchange', { ticket: body.ticket, state: body.state, audience: inkos.origin });
        if (closed || response.destroyed) reject(503, 'BROKER_CLOSED');
        const expires = Math.min(epochMs(data.expires_at), now() + limits.sessionMs);
        if (!positiveInteger(data.user_id) || !validIdentity(data.identity, data.user_id) || !positiveInteger(data.token_id) || !Number.isFinite(expires) || expires <= now()) reject(401, 'INVALID_IDENTITY');
        const tenant = tenants.get(data.user_id);
        if (!tenant) reject(403, 'TENANT_NOT_PROVISIONED');
        if (sessions.size >= limits.maxSessions || tenant.sessions.size >= limits.maxSessionsPerTenant) reject(429, 'SESSION_CAPACITY');
        const oldCookie = cookies(request).get(APP_COOKIE);
        const previous = oldCookie && sessions.get(oldCookie);
        const appCookie = randomToken();
        const session = { cookie: appCookie, identity: Object.freeze({ ...data.identity }), userId: data.user_id, expires,
          tenant, tokenId: data.token_id, operations: new Set() };
        sessions.set(appCookie, session);
        tenant.sessions.add(session);
        tenant.stopped = false;
        if (previous) invalidate(previous);
        response.setHeader('Set-Cookie', [cookie(APP_COOKIE, appCookie, Math.max(1, Math.floor((expires - now()) / 1000))), cookie(PREFLIGHT_COOKIE, '', 0)]);
        response.setHeader('Content-Type', 'application/json; charset=utf-8');
        response.end('{"success":true}');
        return;
      }
      reject(403, 'INTEGRATION_PATH_FORBIDDEN');
    }
    requireOrigin(request, inkos.origin);
    if (!SAFE.has(request.method)) requireMedia(request);
    const credential = cookies(request).get(APP_COOKIE);
    if (!TOKEN.test(credential || '')) reject(401, 'SESSION_REQUIRED');
    const session = sessions.get(credential);
    await live(session);
    security(response, null, /(?:^|\/)preview(?:\/|$)/i.test(info.pathname));
    await proxy(request, response, session);
  }

  async function relay(tenant, request, response) {
    security(response);
    if (closed) reject(503, 'BROKER_CLOSED');
    const info = inspectPath(request.url);
    if (info.search || info.rawPathname !== info.pathname ||
        !((request.method === 'GET' && info.pathname === '/v1/models') ||
          (request.method === 'POST' && ['/v1/chat/completions', '/v1/responses'].includes(info.pathname)))) reject(403, 'RELAY_PATH_FORBIDDEN');
    if (tenant.relayActive >= limits.relayConcurrency || relayActive >= limits.relayGlobalConcurrency) reject(429, 'RELAY_BUSY');
    tenant.relayActive++;
    relayActive++;
    let operation;
    try {
      const parsed = request.method === 'POST' ? await readJson(request, limits.relayBodyBytes) : null;
      let session;
      for (const candidate of [...tenant.sessions]) {
        try { await live(candidate); session = candidate; break; } catch { /* Try another original live session, never another tenant. */ }
      }
      if (!session) reject(401, 'LIVE_SESSION_REQUIRED');
      const context = await relayContext(session);
      const model = parsed?.body.model;
      if (parsed && (typeof model !== 'string' || !context.models.includes(model))) reject(403, 'MODEL_FORBIDDEN');
      if (response.destroyed) return;
      operation = register(session, response);
      operation.contextToken = context.token_id;
      operation.model = model || null;
      const headers = { Accept: request.headers.accept || 'application/json', Authorization: `Bearer ${context.api_key}` };
      if (parsed) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = parsed.bytes.length; }
      const upstream = transport.request(new URL(info.pathname, internal), { method: request.method, headers, agent: modelAgent });
      operation.attach(upstream);
      const deadline = setTimeout(() => upstream.destroy(new Rejection(504, 'RELAY_TIMEOUT')), limits.headerTimeoutMs);
      deadline.unref();
      try {
        await new Promise((resolve, rejectPromise) => {
          upstream.once('error', rejectPromise);
          upstream.once('response', async incoming => {
            clearTimeout(deadline);
            operation.attach(incoming);
            try {
              response.writeHead(incoming.statusCode, filteredHeaders(incoming.headers, RESPONSE_HEADERS));
              await pipeline(incoming, response);
              resolve();
            } catch (error) { rejectPromise(error); }
          });
          upstream.end(parsed?.bytes);
        });
      } finally { clearTimeout(deadline); upstream.destroy(); }
    } finally {
      operation?.finish();
      tenant.relayActive--;
      relayActive--;
    }
  }

  function makeServer(handler) {
    const server = http.createServer({ maxHeaderSize: 16 * 1024 }, (request, response) => {
      void handler(request, response).catch(error => failure(response, error));
    });
    server.requestTimeout = 60_000;
    server.headersTimeout = 15_000;
    server.keepAliveTimeout = 5000;
    server.maxHeadersCount = 64;
    server.on('connect', (request, socket) => { socket.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n'); });
    server.on('upgrade', (request, socket) => { socket.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n'); });
    server.on('clientError', (error, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); });
    return server;
  }
  const server = makeServer(browser);
  const bound = [];
  try {
    for (const tenant of tenants.values()) {
      await removeStaleSocket(tenant.relaySocket);
      tenant.relayServer = makeServer((request, response) => relay(tenant, request, response));
      await new Promise((resolve, rejectPromise) => {
        tenant.relayServer.once('error', rejectPromise);
        tenant.relayServer.listen(tenant.relaySocket, resolve);
      });
      bound.push(tenant);
      await chmod(tenant.relaySocket, 0o600);
    }
    // Restart means no sessions survive; halt any previous children before serving browser traffic.
    await Promise.all([...tenants.values()].map(tenant => control(tenant, 'stop')));
    timer = setInterval(() => { void sweep().catch(() => {}); }, limits.introspectIntervalMs);
    timer.unref();
  } catch (error) {
    closed = true;
    for (const tenant of bound) {
      tenant.relayServer.closeAllConnections();
      await new Promise(resolve => tenant.relayServer.close(resolve));
      await unlink(tenant.relaySocket).catch(() => {});
    }
    privateAgent.destroy();
    modelAgent.destroy();
    throw error;
  }

  return {
    server,
    async listen({ port = 8080, host = '0.0.0.0' } = {}) {
      if (closed) throw new Error('Broker closed');
      await new Promise((resolve, rejectPromise) => {
        const onError = error => { server.removeListener('listening', onListening); rejectPromise(error); };
        const onListening = () => { server.removeListener('error', onError); resolve(); };
        server.once('error', onError);
        server.once('listening', onListening);
        server.listen(port, host);
      });
      return server.address();
    },
    sweep,
    stats() { return { states: states.size, sessions: sessions.size, tenants: tenants.size, relayActive, workerActive }; },
    async close() {
      if (closePromise) return await closePromise;
      if (closed) return;
      // Close the admission gate before awaiting controls/authority responses.
      closed = true;
      clearInterval(timer);
      closePromise = (async () => {
        for (const session of [...sessions.values()]) invalidate(session);
        states.clear();
        for (const tenant of tenants.values()) for (const operation of [...tenant.operations]) operation.abort();
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
        // Still attempt every stop during authority outages; report failures.
        const stops = await Promise.allSettled([...tenants.values()].map(tenant => control(tenant, 'stop')));
        for (const tenant of tenants.values()) {
          tenant.relayServer.closeAllConnections();
          await new Promise(resolve => tenant.relayServer.close(resolve));
          await unlink(tenant.relaySocket).catch(() => {});
        }
        privateAgent.destroy();
        modelAgent.destroy();
        if (stops.some(result => result.status === 'rejected')) reject(503, 'WORKER_STOP_FAILED');
      })();
      return await closePromise;
    },
  };
}
