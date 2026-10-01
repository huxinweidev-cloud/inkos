import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';

async function boundedFile(filename, maxBytes) {
  if (typeof filename !== 'string' || !filename || !path.isAbsolute(filename) || path.resolve(filename) !== filename) throw new Error('Required configuration file missing');
  const before = await lstat(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.size === 0 || before.size > maxBytes || await realpath(filename) !== filename) throw new Error('Invalid configuration file');
  // Defend the last component at open as well as lstat; inspect the actual fd
  // to detect a file replacement. Parent mounts still must be operator-owned.
  const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const actual = await file.stat();
    if (!actual.isFile() || actual.dev !== before.dev || actual.ino !== before.ino || actual.size === 0 || actual.size > maxBytes) throw new Error('Configuration file changed');
    const bytes = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
    if (bytesRead === 0 || bytesRead > maxBytes) throw new Error('Configuration file too large');
    return bytes.subarray(0, bytesRead).toString('utf8');
  } finally { await file.close(); }
}

export async function loadConfig(env = process.env) {
  const serviceKey = (await boundedFile(env.INKOS_SERVICE_KEY_FILE, 1024)).trim();
  const tenants = JSON.parse(await boundedFile(env.INKOS_TENANTS_FILE, 128 * 1024));
  return {
    inkosOrigin: env.INKOS_ORIGIN,
    newapiOrigin: env.NEWAPI_ORIGIN,
    newapiInternalBase: env.NEWAPI_INTERNAL_BASE,
    serviceKey,
    tenants,
    runtimeRoot: '/runtime',
  };
}
