import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { lstat, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export const HOSTED_SERVICE = 'custom:newapi';
export const PLACEHOLDER_KEY = 'inkos-broker-placeholder-not-a-real-key';

async function rejectSymlink(path) {
  try { if ((await lstat(path)).isSymbolicLink()) throw new Error('Hosted bootstrap symlink denied'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
async function writeJson(path, value) {
  await rejectSymlink(path);
  const temporary = join(dirname(path), `.bootstrap-${randomBytes(12).toString('hex')}`);
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  await rename(temporary, path);
}
export async function fetchBrokerModels(base) {
  const url = new URL(`${base}/models`);
  if (url.hostname !== '127.0.0.1' || url.protocol !== 'http:' || url.pathname !== '/v1/models') throw new Error('Invalid relay base');
  return new Promise((yes, no) => {
    const request = http.get(url, { headers: { Authorization: `Bearer ${PLACEHOLDER_KEY}` }, agent: false }, response => {
      let size = 0;
      const chunks = [];
      response.on('data', chunk => { size += chunk.length; if (size > 1024 * 1024) request.destroy(new Error('Models response too large')); else chunks.push(chunk); });
      response.once('error', no);
      response.once('end', () => {
        try {
          if (response.statusCode !== 200) throw new Error('Models unavailable');
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!Array.isArray(body.data)) throw new Error('Invalid models response');
          const models = [...new Set(body.data.map(model => model.id).filter(id => typeof id === 'string' && id.length > 0 && id.length <= 256 && !/[\u0000-\u001f]/u.test(id)))];
          if (!models.length || models.length > 1000) throw new Error('No bounded broker models');
          yes(models);
        } catch { no(new Error('Invalid broker models')); }
      });
    });
    const timer = setTimeout(() => request.destroy(new Error('Models deadline')), 10_000);
    request.once('close', () => clearTimeout(timer)); request.once('error', no);
  });
}

/** Only NEW private tenant project/HOME; no real model key is ever provided. */
export async function bootstrapHostedProject(root, relayBase) {
  await mkdir(root, { recursive: true, mode: 0o700 });
  const inkos = join(root, '.inkos');
  await rejectSymlink(inkos);
  await mkdir(inkos, { recursive: true, mode: 0o700 });
  await rejectSymlink(join(root, 'inkos.json'));
  let previous = {};
  try { previous = JSON.parse(await readFile(join(root, 'inkos.json'), 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw new Error('Invalid hosted project config'); }
  const models = await fetchBrokerModels(relayBase);
  const model = models.includes(previous.llm?.model) ? previous.llm.model : models[0];
  const config = { name: previous.name || 'Hosted Inkos', version: '0.1.0', language: previous.language === 'en' ? 'en' : 'zh',
    llm: { provider: 'openai', service: HOSTED_SERVICE, configSource: 'studio', baseUrl: relayBase,
      model, defaultModel: model, apiFormat: 'chat', stream: true,
      services: [{ service: 'custom', name: 'newapi', baseUrl: relayBase, models, apiFormat: 'chat', stream: true }] },
    notify: [], researchSearch: { enabled: false, provider: 'tavily' },
    daemon: { maxConcurrentBooks: 1 },
  };
  await writeJson(join(root, 'inkos.json'), config);
  await writeJson(join(inkos, 'secrets.json'), { services: { [HOSTED_SERVICE]: { apiKey: PLACEHOLDER_KEY } } });
  for (const dir of ['works', 'radar']) { await rejectSymlink(join(root, dir)); await mkdir(join(root, dir), { recursive: true, mode: 0o700 }); }
  return config;
}
