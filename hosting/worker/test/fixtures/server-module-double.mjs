// Explicit TEST DOUBLE for production child adapter tests; no Inkos/model simulation claimed.
import http from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
export async function startStudioServer(root, port, options) {
  let runtimeReadDenied = false, runtimeWriteDenied = false;
  const runtime = join(dirname(root), 'runtime', 'studio.sock');
  try { await readFile(runtime); } catch (error) { runtimeReadDenied = error.code === 'ERR_ACCESS_DENIED'; }
  try { await writeFile(runtime, 'should-not-write'); } catch (error) { runtimeWriteDenied = error.code === 'ERR_ACCESS_DENIED'; }
  await new Promise(resolve => {
    http.createServer(async (req, res) => {
      const request = new Request(`http://127.0.0.1:${port}${req.url}`, { headers: req.headers });
      if (!await options.authorize(request)) { res.writeHead(401); res.end('Unauthorized'); return; }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ hostname: options.hostname, origins: options.allowedOrigins, runtimeReadDenied, runtimeWriteDenied, root }));
    }).listen(port, options.hostname, resolve);
  });
}
