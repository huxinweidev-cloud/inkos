import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { bootstrapHostedProject } from './bootstrap.mjs';

const HEADER = 'x-inkos-worker-credential';
function matches(expected, supplied) {
  if (typeof supplied !== 'string' || supplied.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(supplied));
}
async function probe(port, credential) {
  await new Promise((yes, no) => {
    const request = http.get({ hostname: '127.0.0.1', port, path: '/api/v1/profiles', headers: { [HEADER]: credential }, agent: false }, response => {
      response.resume(); response.once('end', () => response.statusCode === 200 ? yes() : no(new Error('Studio not ready')));
    });
    request.setTimeout(3000, () => request.destroy(new Error('Studio deadline'))); request.once('error', no);
  });
}
if (!process.send) throw new Error('Private supervisor IPC required');
const initialDeadline = setTimeout(() => process.exit(1), 10_000);
process.once('message', async message => {
  clearTimeout(initialDeadline);
  let credential = message?.credential;
  if (message?.type !== 'initialize' || typeof credential !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(credential)
    || message.origin !== 'https://inkos.hxwhub.eu.org') return process.exit(1);
  delete message.credential;
  // Supervisor death must not orphan background work; group kill is authoritative.
  process.once('disconnect', () => { credential = null; process.exit(1); });
  try {
    await bootstrapHostedProject(message.root, message.relayBase);
    const { startStudioServer } = await import(pathToFileURL(message.studioModule).href);
    await startStudioServer(message.root, message.port, { staticDir: message.staticDir, hostname: '127.0.0.1',
      allowedOrigins: [message.origin], authorize: request => credential !== null && matches(credential, request.headers.get(HEADER)) });
    await probe(message.port, credential);
    process.send({ type: 'ready' });
  } catch {
    credential = null;
    process.send({ type: 'failed' }, () => process.exit(1));
  }
});
