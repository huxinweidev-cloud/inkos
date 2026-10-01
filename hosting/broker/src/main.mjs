import { loadConfig } from './config.mjs';
import { createBroker } from './broker.mjs';

let broker;
try {
  broker = await createBroker(await loadConfig());
  await broker.listen({ port: 8080, host: '0.0.0.0' });
  // Only fixed lifecycle messages: never stringify request/error/config objects.
  console.info('Inkos broker ready');
  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    const deadline = setTimeout(() => process.exit(1), 10_000);
    deadline.unref();
    try { await broker.close(); clearTimeout(deadline); }
    catch { process.exitCode = 1; }
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
} catch {
  console.error('Inkos broker startup failed; check mounted configuration and Unix socket ownership');
  await broker?.close().catch(() => {});
  process.exitCode = 1;
}
