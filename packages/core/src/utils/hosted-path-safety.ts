import { lstat, realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

/** Public deployment flag; CLI behavior is unchanged unless explicitly hosted. */
export function isHostedMode(): boolean {
  return process.env.INKOS_HOSTED === "1";
}

function denied(): never {
  throw Object.assign(new Error("Hosted file access denied"), { code: "HOSTED_PATH_FORBIDDEN" });
}

function contained(root: string, path: string): boolean {
  const child = relative(root, path);
  return child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child);
}

function sensitive(root: string, path: string): boolean {
  const parts = relative(root, path).split(sep).map(part => part.toLowerCase());
  if (parts.some(part => part === ".env" || part.startsWith(".env.")
    || part === "runtime" || part === ".ssh" || part === ".aws"
    || /^(?:secrets?|credentials?)(?:[._-]|$)/u.test(part))) return true;
  const inkos = parts.indexOf(".inkos");
  // Uploaded author input and ingested material are intentionally readable.
  return inkos !== -1 && !["uploads", "materials"].includes(parts[inkos + 1] ?? "");
}

/** Check both the lexical name and the canonical target, including parent links. */
export async function hostedReadablePath(projectRoot: string, requestedPath: string): Promise<string> {
  const path = resolve(projectRoot, requestedPath);
  if (!isHostedMode()) return path;
  const root = resolve(projectRoot);
  if (!requestedPath || requestedPath.includes("\0") || requestedPath.split(/[\\/]/u).includes("..")
    || !contained(root, path) || sensitive(root, path)) denied();
  const canonicalRoot = await realpath(root);
  const canonicalPath = await realpath(path);
  if (!contained(canonicalRoot, canonicalPath) || sensitive(canonicalRoot, canonicalPath)) denied();
  return canonicalPath;
}

/** Restrict hosted translation writes to that Work's exports directory. */
export async function hostedExportPath(projectRoot: string, exportRoot: string, requestedPath: string): Promise<string> {
  if (!isHostedMode()) return requestedPath;
  const root = resolve(projectRoot);
  const exports = resolve(exportRoot);
  const path = resolve(projectRoot, requestedPath);
  if (requestedPath.includes("\0") || requestedPath.split(/[\\/]/u).includes("..")
    || !contained(root, exports) || path === exports || !contained(exports, path)) denied();
  const canonicalRoot = await realpath(root);
  if (sensitive(root, path)) denied();
  // realpath(leaf) returns ENOENT for a dangling symlink. Inspect EVERY
  // lexical component first, so missing targets do not bypass write policy.
  for (let component = path; component !== root; component = dirname(component)) {
    try { if ((await lstat(component)).isSymbolicLink()) denied(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
  // Resolve the nearest existing ancestor, so a nonexistent filename cannot
  // bypass a symlink in an existing parent directory (or the file itself).
  let ancestor = path;
  while (true) {
    try {
      const canonical = await realpath(ancestor);
      if (canonical !== ancestor || !contained(canonicalRoot, canonical)) denied();
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = dirname(ancestor);
      if (parent === ancestor) denied();
      ancestor = parent;
    }
  }
  return path;
}
