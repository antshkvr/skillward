// One repository: a shallow, blobless clone with a sparse checkout of only the files skillward's discovery reads, so
// third-party code never lands on disk in bulk. Nothing fetched is ever executed: no hooks, no submodules, no LFS
// filters, symlinks are checked out as plain files.
import { rm } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { HOOK_FILE } from "../../src/discovery/index.js";
import { hookScriptPaths } from "../../src/discovery/hook-targets.js";
import { run } from "./common.js";
import { selectAgentFiles, selectHookScripts, sparsePattern } from "./lib.js";

export interface FetchMeta {
  repo: string;
  status: "ok" | "empty" | "error";
  sha?: string;
  files?: number;
  /** Of `files`, scripts fetched because a hook command names them. */
  hookScripts?: number;
  truncated?: number;
  unportable?: number;
  error?: string;
  fetchedAt: string;
}

// Hardening for untrusted repositories, applied to every git command.
const SAFE = [
  "-c", "core.symlinks=false",
  "-c", "core.longpaths=true",
  "-c", "core.hooksPath=/dev/null",
  "-c", "core.fsmonitor=false",
  "-c", "protocol.file.allow=never",
  "-c", "submodule.recurse=false",
  "-c", "filter.lfs.smudge=",
  "-c", "filter.lfs.process=",
  "-c", "filter.lfs.required=false",
  // On Windows git rejects the whole checkout when any path in the tree is invalid there, even outside the sparse
  // set. Only selected paths are written, and selectAgentFiles(portable) refuses unsafe names (incl. .git aliases).
  "-c", "core.protectNTFS=false",
];

const git = (args: string[], options: { cwd?: string; input?: string; timeoutMs?: number } = {}) =>
  run("git", [...SAFE, ...args], { timeoutMs: 180_000, ...options });

/** Clones `repo` into `target` (replacing it) and checks out its agent files and the scripts their hooks run. */
export async function fetchRepo(repo: string, target: string, options: { maxFiles: number }): Promise<FetchMeta> {
  await rm(target, { recursive: true, force: true });
  const fail = async (step: string, stderr: string): Promise<FetchMeta> => {
    await rm(target, { recursive: true, force: true });
    return { repo, status: "error", error: `${step}: ${stderr.trim().split("\n").slice(-1)[0] ?? ""}`, fetchedAt: new Date().toISOString() };
  };

  const url = `https://github.com/${repo}.git`;
  let res = await git(["clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout", "--single-branch", "--no-tags", url, target]);
  if (res.code !== 0) return fail("clone", res.stderr);
  res = await git(["rev-parse", "HEAD"], { cwd: target });
  if (res.code !== 0) return fail("rev-parse", res.stderr);
  const sha = res.stdout.trim();
  res = await git(["ls-tree", "-r", "-z", "--full-tree", "--name-only", "HEAD"], { cwd: target });
  if (res.code !== 0) return fail("ls-tree", res.stderr);

  const tree = res.stdout.split("\0").filter(Boolean);
  const selection = selectAgentFiles(tree, { maxFiles: options.maxFiles, portable: true });
  const base = { repo, sha, truncated: selection.truncated, unportable: selection.unportable, fetchedAt: new Date().toISOString() };
  if (!selection.files.length) {
    await rm(target, { recursive: true, force: true });
    return { ...base, status: "empty", files: 0 };
  }

  const checkout = async (files: string[]) => {
    const r = await git(["sparse-checkout", "set", "--no-cone", "--stdin"], { cwd: target, input: files.map(sparsePattern).join("\n") + "\n" });
    if (r.code !== 0) return { step: "sparse-checkout", ...r };
    return { step: "checkout", ...(await git(["checkout", "-q"], { cwd: target, timeoutMs: 600_000 })) };
  };
  const first = await checkout(selection.files);
  if (first.code !== 0) return fail(first.step, first.stderr);

  // Second pass: the scripts hook commands name can live anywhere in the repo (`scripts/guard.sh`, `.github/x.js`).
  // Read the checked-out hook files the way discovery does and fetch what they point at.
  const named: string[] = [];
  for (const file of selection.files.filter((f) => HOOK_FILE.test(f))) {
    for (const hook of await hookScriptPaths(join(target, file), target)) named.push(relative(target, hook.absPath).split(sep).join("/"));
  }
  const hookScripts = selectHookScripts(tree, selection.files, named, { portable: true });
  if (hookScripts.length) {
    const second = await checkout([...selection.files, ...hookScripts]);
    if (second.code !== 0) return fail(`${second.step} (hook scripts)`, second.stderr);
  }
  return { ...base, status: "ok", files: selection.files.length + hookScripts.length, hookScripts: hookScripts.length };
}
