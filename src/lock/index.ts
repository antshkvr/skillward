import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join, posix } from "node:path";
import { createPatch } from "diff";
import type { Config } from "../config/index.js";
import { discover, type DiscoveryOptions } from "../discovery/index.js";
import { CLAUDE_JSON } from "../parsers/index.js";
import { claudeJsonDescend, claudeJsonMcpSections, parseJsonTree, toValue } from "../parsers/json-tree.js";
import { redactSecrets } from "../rules/SW016-secret-in-config.js";
import { escapeInvisible } from "../text.js";
import { TARGET_KINDS, type Target, type TargetKind } from "../types.js";

export const LOCK_FILE_NAME = "skillward.lock";
export const LOCK_VERSION = 1;
/** Where `lock --global` keeps its lockfile and snapshots, in the home directory: outside `~/.claude`, which it locks. */
export const GLOBAL_STATE_DIR = ".skillward";
/** Content-addressed copies of locked text files, so `verify` can show what changed. */
export const SNAPSHOT_DIR = join(".skillward", "snapshots");
/** Text files above this size get a hash but no snapshot. */
const MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024;
const MAX_DIFF_LINES = 200;
const HASH = /^sha256:[0-9a-f]{64}$/;

export interface LockEntry {
  path: string;
  kind: TargetKind;
  /** Where the target came from, e.g. `github:owner/repo@ref`. Maintained by hand; preserved by `lock`. */
  source?: string;
  /** File path relative to the target (its basename for single-file targets) → `sha256:<hex>`. */
  files: Record<string, string>;
  lockedAt: string;
}

export interface Lockfile {
  version: typeof LOCK_VERSION;
  entries: LockEntry[];
}

export class LockError extends Error {}

interface CurrentEntry {
  path: string;
  kind: TargetKind;
  /** Relative file key → absolute path and hash. */
  files: Map<string, CurrentFile>;
}

interface CurrentFile {
  absPath: string;
  displayPath: string;
  hash: string;
  /** What is locked when it isn't the whole file (the MCP sections of `~/.claude.json`). */
  content?: Buffer;
}

/** What to lock: a project, or the user's global agent configuration. */
export interface LockScope {
  /** Project directory; ignored with `global`. */
  root: string;
  config: Config;
  /** `~/.claude` and the MCP servers in `~/.claude.json`, locked in `~/.skillward/skillward.lock`. */
  global?: boolean;
  /** Overrides the home directory (tests). */
  homeDir?: string;
}

interface ResolvedScope {
  /** Directory holding the lockfile. */
  stateDir: string;
  snapshotDir: string;
  /** The lockfile as shown to the user. */
  lockName: string;
  relock: string;
  discovery: DiscoveryOptions;
}

function resolveScope(scope: LockScope): ResolvedScope {
  if (!scope.global) {
    return { stateDir: scope.root, snapshotDir: join(scope.root, SNAPSHOT_DIR), lockName: LOCK_FILE_NAME, relock: "skillward lock", discovery: { path: scope.root, ignore: scope.config.ignore } };
  }
  const home = scope.homeDir ?? homedir();
  return {
    stateDir: join(home, GLOBAL_STATE_DIR),
    snapshotDir: join(home, GLOBAL_STATE_DIR, "snapshots"),
    lockName: `~/${GLOBAL_STATE_DIR}/${LOCK_FILE_NAME}`,
    relock: "skillward lock --global",
    discovery: { path: home, globalOnly: true, homeDir: home },
  };
}

/**
 * `~/.claude.json` is rewritten all the time (history, counters, per-project state), so only its MCP servers are
 * locked: the `mcpServers` sections as canonical JSON, keys sorted, projects without servers left out.
 */
export function claudeJsonLockedText(text: string): string {
  const tree = parseJsonTree(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text, { descend: claudeJsonDescend });
  if (!tree) return '{ "error": "invalid JSON" }\n';
  const locked: { mcpServers?: unknown; projects?: Record<string, unknown> } = {};
  for (const { scope, node } of claudeJsonMcpSections(tree)) {
    const servers = toValue(node);
    if (isEmptyObject(servers)) continue;
    if (scope === undefined) locked.mcpServers = servers;
    else (locked.projects ??= {})[scope] = { mcpServers: servers };
  }
  return JSON.stringify(sortKeys(locked), null, 2) + "\n";
}

const isEmptyObject = (v: unknown) => typeof v === "object" && v !== null && !Array.isArray(v) && Object.keys(v).length === 0;

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys((value as Record<string, unknown>)[k])]));
}

async function hashFile(absPath: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(absPath)) hash.update(chunk as Buffer);
  return `sha256:${hash.digest("hex")}`;
}

function fileKey(target: Target, displayPath: string, hookTarget: boolean): string {
  // Hook scripts can share a basename (two `run.sh` in different folders): keep their project-relative path.
  if (hookTarget) return displayPath;
  if (target.kind !== "skill") return posix.basename(displayPath);
  return target.path === "." ? displayPath : displayPath.slice(target.path.length + 1);
}

/** Hashes every file of every target. Never follows symlinks (discovery skips them). */
async function currentEntries(discovery: DiscoveryOptions): Promise<CurrentEntry[]> {
  const { targets } = await discover(discovery);
  const entries: CurrentEntry[] = [];
  for (const target of targets) {
    const files = new Map<string, CurrentFile>();
    for (const f of target.files) {
      // The lock's own state must never be part of what it locks (matters when the root is a skill).
      if (f.path === LOCK_FILE_NAME || f.path.startsWith(".skillward/")) continue;
      const key = fileKey(target, f.path, Boolean(f.hookTarget));
      if (basename(f.absPath) === CLAUDE_JSON) {
        const content = Buffer.from(claudeJsonLockedText(await readFile(f.absPath, "utf8")));
        files.set(key, { absPath: f.absPath, displayPath: f.path, hash: `sha256:${createHash("sha256").update(content).digest("hex")}`, content });
      } else {
        files.set(key, { absPath: f.absPath, displayPath: f.path, hash: await hashFile(f.absPath) });
      }
    }
    if (files.size) entries.push({ path: target.path, kind: target.kind, files });
  }
  return entries.sort((a, b) => cmp(a.path, b.path));
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function sameFiles(a: Record<string, string>, b: Record<string, string>): boolean {
  const ka = Object.keys(a);
  return ka.length === Object.keys(b).length && ka.every((k) => a[k] === b[k]);
}

/** Reads the lockfile in `dir` (a project root, or `~/.skillward` for the global lock). */
export async function readLock(dir: string): Promise<Lockfile | undefined> {
  let raw: string;
  try {
    raw = await readFile(join(dir, LOCK_FILE_NAME), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new LockError(`cannot read ${LOCK_FILE_NAME}: ${(err as Error).message}`);
  }
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new LockError(`invalid JSON in ${LOCK_FILE_NAME}: ${(err as Error).message}`);
  }
  return validateLock(data);
}

/** The lockfile is untrusted input too (it arrives with the repo): validate everything used as a path. */
export function validateLock(data: unknown): Lockfile {
  const fail = (msg: string): never => {
    throw new LockError(`${LOCK_FILE_NAME}: ${msg}`);
  };
  if (typeof data !== "object" || data === null) fail("must be a JSON object");
  const obj = data as { version?: unknown; entries?: unknown };
  if (obj.version !== LOCK_VERSION) fail(`unsupported version ${JSON.stringify(obj.version)} (expected ${LOCK_VERSION})`);
  if (!Array.isArray(obj.entries)) fail(`"entries" must be an array`);
  const entries = (obj.entries as unknown[]).map((e, i): LockEntry => {
    const entry = e as Partial<LockEntry>;
    if (typeof entry?.path !== "string") fail(`entries[${i}].path must be a string`);
    if (!TARGET_KINDS.includes(entry.kind as TargetKind)) fail(`entries[${i}].kind is invalid`);
    if (entry.source !== undefined && typeof entry.source !== "string") fail(`entries[${i}].source must be a string`);
    if (typeof entry.lockedAt !== "string") fail(`entries[${i}].lockedAt must be a string`);
    if (typeof entry.files !== "object" || entry.files === null) fail(`entries[${i}].files must be an object`);
    for (const [k, v] of Object.entries(entry.files as Record<string, unknown>)) {
      if (typeof v !== "string" || !HASH.test(v)) fail(`entries[${i}].files["${k}"] must be "sha256:<64 hex>"`);
    }
    return entry as LockEntry;
  });
  return { version: LOCK_VERSION, entries };
}

export interface LockResult {
  lock: Lockfile;
  /** The lockfile as shown to the user. */
  lockName: string;
  /** Entries whose files changed since the previous lock (or are new). */
  updated: string[];
  snapshots: number;
}

/** Creates or updates `skillward.lock` (and snapshots) in `root`. */
export async function lock(options: LockScope & { snapshots?: boolean; now?: Date }): Promise<LockResult> {
  const scope = resolveScope(options);
  const previous = await readLock(scope.stateDir);
  const lockedAt = (options.now ?? new Date()).toISOString().replace(/\.\d{3}Z$/, "Z");
  const current = await currentEntries(scope.discovery);
  const updated: string[] = [];

  const entries = current.map((c): LockEntry => {
    const files = Object.fromEntries([...c.files].sort(([a], [b]) => cmp(a, b)).map(([k, v]) => [k, v.hash]));
    const prev = previous?.entries.find((e) => e.path === c.path);
    const unchanged = prev && prev.kind === c.kind && sameFiles(prev.files, files);
    if (!unchanged) updated.push(c.path);
    return {
      path: c.path,
      kind: c.kind,
      ...(prev?.source ? { source: prev.source } : {}),
      files,
      lockedAt: unchanged ? prev.lockedAt : lockedAt,
    };
  });

  const result: Lockfile = { version: LOCK_VERSION, entries };
  await mkdir(scope.stateDir, { recursive: true });
  await writeFile(join(scope.stateDir, LOCK_FILE_NAME), JSON.stringify(result, null, 2) + "\n", "utf8");

  let snapshots = 0;
  if (options.snapshots !== false) snapshots = await writeSnapshots(scope.snapshotDir, current);
  return { lock: result, lockName: scope.lockName, updated, snapshots };
}

async function writeSnapshots(dir: string, current: CurrentEntry[]): Promise<number> {
  await mkdir(dir, { recursive: true });
  const keep = new Set<string>();
  for (const entry of current) {
    for (const file of entry.files.values()) {
      const hex = file.hash.slice("sha256:".length);
      const content = file.content ?? (await readFile(file.absPath));
      if (content.length > MAX_SNAPSHOT_BYTES || content.subarray(0, 8000).includes(0)) continue;
      keep.add(hex);
      // Snapshots exist to show diffs, which never print secrets: don't keep a second copy of them either.
      await writeFile(join(dir, hex), redactSecrets(content.toString("utf8")), "utf8");
    }
  }
  // Drop snapshots no longer referenced by the lock.
  for (const name of await readdir(dir)) {
    if (/^[0-9a-f]{64}$/.test(name) && !keep.has(name)) await rm(join(dir, name));
  }
  return keep.size;
}

export type ChangeStatus = "added" | "removed" | "changed";

export interface FileChange {
  status: ChangeStatus;
  /** Target the file belongs to. */
  target: string;
  /** Display path of the file. */
  path: string;
  /** Absolute path (absent for removed files). */
  absPath?: string;
  oldHash?: string;
  newHash?: string;
  /** Unified diff for changed text files, escaped and truncated. */
  diff?: string;
  /** Why there is no diff. */
  note?: string;
}

export interface VerifyResult {
  lockPath: string;
  /** The lockfile as shown to the user, and the command that accepts changes. */
  lockName: string;
  relock: string;
  changes: FileChange[];
  targetsAdded: string[];
  targetsRemoved: string[];
}

export async function verify(options: LockScope): Promise<VerifyResult> {
  const scope = resolveScope(options);
  const previous = await readLock(scope.stateDir);
  if (!previous) throw new LockError(`${LOCK_FILE_NAME} not found in ${scope.stateDir} — run \`${scope.relock}\` first`);
  const current = await currentEntries(scope.discovery);
  const changes: FileChange[] = [];
  const displayOf = (entry: { path: string; kind: TargetKind }, key: string) =>
    entry.kind === "skill" ? (entry.path === "." ? key : `${entry.path}/${key}`) : entry.path;

  const locked = new Map(previous.entries.map((e) => [e.path, e]));
  const targetsAdded = current.filter((c) => !locked.has(c.path)).map((c) => c.path);
  const targetsRemoved = previous.entries.filter((e) => !current.some((c) => c.path === e.path)).map((e) => e.path);

  for (const entry of current) {
    const old = locked.get(entry.path)?.files ?? {};
    for (const [key, file] of entry.files) {
      const oldHash = old[key];
      if (!oldHash) {
        changes.push({ status: "added", target: entry.path, path: file.displayPath, absPath: file.absPath, newHash: file.hash });
      } else if (oldHash !== file.hash) {
        const change: FileChange = {
          status: "changed",
          target: entry.path,
          path: file.displayPath,
          absPath: file.absPath,
          oldHash,
          newHash: file.hash,
        };
        Object.assign(change, await textDiff(scope.snapshotDir, file, oldHash));
        changes.push(change);
      }
    }
    for (const [key, hash] of Object.entries(old)) {
      if (!entry.files.has(key)) changes.push({ status: "removed", target: entry.path, path: displayOf(entry, key), oldHash: hash });
    }
  }
  for (const path of targetsRemoved) {
    const entry = locked.get(path)!;
    for (const [key, hash] of Object.entries(entry.files)) {
      changes.push({ status: "removed", target: path, path: displayOf(entry, key), oldHash: hash });
    }
  }

  changes.sort((a, b) => cmp(a.path, b.path));
  const lockPath = join(scope.stateDir, LOCK_FILE_NAME);
  return { lockPath, lockName: scope.lockName, relock: scope.relock, changes, targetsAdded, targetsRemoved };
}

async function textDiff(snapshotDir: string, file: CurrentFile, oldHash: string): Promise<Pick<FileChange, "diff" | "note">> {
  const path = file.displayPath;
  const snapshot = join(snapshotDir, oldHash.slice("sha256:".length));
  let before: Buffer;
  try {
    if ((await stat(snapshot)).size > MAX_SNAPSHOT_BYTES) return { note: "no snapshot of the locked version" };
    before = await readFile(snapshot);
  } catch {
    return { note: `no snapshot of the locked version (lock keeps snapshots unless --no-snapshots)` };
  }
  const after = file.content ?? (await readFile(file.absPath));
  if (after.length > MAX_SNAPSHOT_BYTES) return { note: "file too large to diff" };
  if (before.subarray(0, 8000).includes(0) || after.subarray(0, 8000).includes(0)) return { note: "binary file changed" };

  // Both sides masked: snapshots are stored masked, and the diff must not print a new secret either.
  const [old, now] = [redactSecrets(before.toString("utf8")), redactSecrets(after.toString("utf8"))];
  if (old === now) return { note: "only masked secret values changed" };
  const patch = createPatch(path, old, now, "locked", "current", { context: 3 });
  // Drop the "Index:"/"===" and ---/+++ headers; the file name is printed by the reporter.
  const lines = patch.split("\n").slice(4).filter((l, i, all) => i < all.length - 1 || l !== "");
  const shown = lines.slice(0, MAX_DIFF_LINES).map((l) => escapeInvisible(l));
  if (lines.length > MAX_DIFF_LINES) shown.push(`… ${lines.length - MAX_DIFF_LINES} more diff line(s)`);
  return { diff: shown.join("\n") };
}
