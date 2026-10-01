import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hostedExportPath, hostedReadablePath } from '../utils/hosted-path-safety.js';
import { createReadTool, createGrepTool, createLsTool } from '../agent/agent-tools.js';
import { loadChapterSource } from '../agent/chapter-import-source.js';
import { extractTranslationSource } from '../translation/source.js';
import { createTranslationProjectFromFile, writeTranslationExport } from '../translation/index.js';
import { ingestMaterial } from '../materials/ingest.js';
import { loadCreationSource } from '../agent/creation-source.js';

// All secrets below are synthetic fixtures, never deployment credentials.
describe('hosted path boundaries', () => {
  let base: string, root: string, outside: string;
  beforeEach(async () => {
    vi.stubEnv('INKOS_HOSTED', '1');
    base = await mkdtemp(join(tmpdir(), 'inkos-hosted-'));
    root = join(base, 'project'); outside = join(base, 'outside');
    await mkdir(join(root, 'works', 'book', 'source', 'story'), { recursive: true });
    await mkdir(join(root, '.inkos', 'uploads'), { recursive: true });
    await mkdir(outside);
    await writeFile(join(outside, 'private.md'), 'synthetic-secret');
    await writeFile(join(root, '.env'), 'synthetic-secret');
    await writeFile(join(root, 'credentials.env'), 'synthetic-secret');
    await writeFile(join(root, '.inkos', 'secrets.json'), 'synthetic-secret');
    await writeFile(join(root, '.inkos', 'uploads', 'input.md'), '# One\n\nSafe author input.');
    await symlink(outside, join(root, 'external'));
    await symlink(join(root, 'credentials.env'), join(root, 'credential-alias.md'));
  });
  afterEach(async () => { vi.unstubAllEnvs(); await rm(base, { recursive: true, force: true }); });

  it('denies lexical traversal, outside absolute paths, direct secrets and symlink aliases', async () => {
    for (const path of ['../outside/private.md', join(outside, 'private.md'), '.env', 'credentials.env', '.inkos/secrets.json',
      'external/private.md', 'credential-alias.md', 'works/book/source/../../../../outside/private.md', '/runtime/relay.sock']) {
      await expect(hostedReadablePath(root, path)).rejects.toMatchObject({ code: 'HOSTED_PATH_FORBIDDEN' });
    }
    expect(await readFile(await hostedReadablePath(root, '.inkos/uploads/input.md'), 'utf8')).toContain('Safe author input');
    await symlink(join(root, '.inkos', 'uploads'), join(root, 'safe-alias'));
    expect(await hostedReadablePath(root, 'safe-alias/input.md')).toBe(join(root, '.inkos', 'uploads', 'input.md'));
  });

  it('gates generic reads, chapter imports, translation, materials and creation through canonical policy', async () => {
    const read = createReadTool(root, { scope: 'project', allowSystemPaths: true });
    for (const path of ['credentials.env', '.inkos/secrets.json', 'external/private.md']) {
      await expect(read.execute('test', { path })).rejects.toMatchObject({ code: 'HOSTED_PATH_FORBIDDEN' });
      await expect(loadChapterSource(root, join(root, path))).rejects.toMatchObject({ code: 'HOSTED_PATH_FORBIDDEN' });
      await expect(extractTranslationSource(root, { filePath: path, sourceLanguage: 'en', targetLanguage: 'zh' })).rejects.toMatchObject({ code: 'HOSTED_PATH_FORBIDDEN' });
      await expect(ingestMaterial(root, { sourceKind: 'file', filePath: path })).rejects.toMatchObject({ code: 'HOSTED_PATH_FORBIDDEN' });
      await expect(loadCreationSource({ projectRoot: root, sourcePath: path, purpose: 'reference' })).rejects.toMatchObject({ code: 'HOSTED_PATH_FORBIDDEN' });
    }
    expect((await loadChapterSource(root, join(root, '.inkos/uploads/input.md'))).chapters[0]?.content).toContain('Safe author input');
  });

  it('does not allow grep/ls to follow a Work symlink outside the project', async () => {
    await symlink(outside, join(root, 'works', 'book', 'source', 'story', 'escape'));
    await expect(createGrepTool(root).execute('test', { bookId: 'book', pattern: 'secret' })).rejects.toThrow('Hosted file access denied');
    await expect(createLsTool(root).execute('test', { bookId: 'book', subdir: 'story/escape' })).rejects.toThrow('Hosted file access denied');
  });

  it('keeps nonexistent export filenames contained and rejects live AND dangling file/parent symlinks', async () => {
    const exports = join(root, 'works/book/source/exports');
    expect(await hostedExportPath(root, exports, join(exports, 'new/deep/file.md'))).toBe(join(exports, 'new/deep/file.md'));
    await mkdir(exports);
    await symlink(join(outside, 'not-created.md'), join(exports, 'dangling.md'));
    await symlink(outside, join(exports, 'external'));
    await symlink(join(root, '.inkos'), join(exports, 'internal-secret'));
    for (const path of [join(outside, 'escaped.md'), join(exports, '../escaped.md'), join(exports, 'dangling.md'),
      join(exports, 'external/new.md'), join(exports, 'internal-secret/secrets.json'), exports]) {
      await expect(hostedExportPath(root, exports, path)).rejects.toMatchObject({ code: 'HOSTED_PATH_FORBIDDEN' });
    }
  });

  it('translation export accepts only that Work exports directory in hosted mode', async () => {
    const created = await createTranslationProjectFromFile(root, { filePath: '.inkos/uploads/input.md', sourceLanguage: 'en', targetLanguage: 'zh' });
    await expect(writeTranslationExport(root, created.manifest.id, { outputPath: join(outside, 'export.md') })).rejects.toMatchObject({ code: 'HOSTED_PATH_FORBIDDEN' });
    const exported = await writeTranslationExport(root, created.manifest.id);
    expect(exported.outputPath).toContain(`/works/${created.manifest.id}/source/exports/`);
    expect(await readFile(exported.outputPath, 'utf8')).toContain('One');
  });

  it('normal CLI still reads external chapter files/secrets and returns unrestricted export paths', async () => {
    vi.stubEnv('INKOS_HOSTED', '0');
    expect(await hostedReadablePath(root, 'credentials.env')).toBe(join(root, 'credentials.env'));
    expect((await loadChapterSource(root, join(outside, 'private.md'))).chapters[0]?.content).toBe('synthetic-secret');
    expect(await hostedExportPath(root, join(root, 'exports'), '../normal-cli-export.md')).toBe('../normal-cli-export.md');
  });
});
