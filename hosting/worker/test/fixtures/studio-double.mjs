// Explicit Studio TEST DOUBLE: real IPC, loopback HTTP and descendant process.
// It is NOT the production Inkos server or a real model response.
import http from 'node:http';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
process.once('message', init => {
  const credential = init.credential;
  delete init.credential;
  const descendant = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore', env: { PATH: process.env.PATH } });
  const server = http.createServer((req, res) => {
    if (req.headers['x-inkos-worker-credential'] !== credential) { res.writeHead(401); res.end('Unauthorized'); return; }
    if (req.url === '/sse') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.write('data: ready\n\n');
      const timer = setInterval(() => res.write('data: alive\n\n'), 20); res.once('close', () => clearInterval(timer)); return;
    }
    let bytes = '';
    req.on('data', chunk => bytes += chunk);
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ pid: process.pid, descendant: descendant.pid, headers: Object.keys(req.headers), origin: req.headers.origin,
        home: process.env.HOME, root: process.cwd(), parentSecretPresent: Boolean(process.env.PARENT_SYNTHETIC_SECRET),
        inEnvironment: Object.values(process.env).some(value => value.includes(credential)),
        inArgv: [...process.argv, ...process.execArgv].some(value => value.includes(credential)),
        inProcEnvironment: readFileSync('/proc/self/environ').includes(Buffer.from(credential)),
        inProcCmdline: readFileSync('/proc/self/cmdline').includes(Buffer.from(credential)),
        fingerprint: createHash('sha256').update(credential).digest('hex'), bytes }));
    });
  });
  server.listen(init.port, '127.0.0.1', () => process.send({ type: 'ready' }));
});
