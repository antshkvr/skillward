// Step 2: fetch the candidates. Each repo is a shallow, blobless clone with a sparse checkout of only the files
// skillward's discovery reads, so third-party code never lands on disk in bulk. Nothing fetched is ever executed:
// no hooks, no submodules, no LFS filters, symlinks are checked out as plain files.
import { rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { corpusArgs, paths, readJson, run, writeJson } from "./common.js";
import { pool, repoDirName, selectAgentFiles, sparsePattern, type Candidate } from "./lib.js";

export interface FetchMeta {
  repo: string;
  status: "ok" | "empty" | "error";
  sha?: string;
  files?: number;
  truncated?: number;
  unportable?: number;
  error?: string;
  fetchedAt: string;
}

const { dir, values } = corpusArgs({
  concurrency: { type: "string", default: "6" },
  "max-files": { type: "string", default: "1500" },
  refetch: { type: "boolean", default: false },
  limit: { type: "string" },
});
const p = paths(dir);
const { candidates } = await readJson<{ candidates: Candidate[] }>(p.candidates);
const list = values.limit ? candidates.slice(0, Number(values.limit)) : candidates;
const maxFiles = Number(values["max-files"]);

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

async function fetchRepo(repo: string): Promise<FetchMeta> {
  const target = join(p.checkouts, repoDirName(repo));
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
  const selection = selectAgentFiles(tree, { maxFiles, portable: true });
  const base = { repo, sha, truncated: selection.truncated, unportable: selection.unportable, fetchedAt: new Date().toISOString() };
  if (!selection.files.length) {
    await rm(target, { recursive: true, force: true });
    return { ...base, status: "empty", files: 0 };
  }

  res = await git(["sparse-checkout", "set", "--no-cone", "--stdin"], { cwd: target, input: selection.files.map(sparsePattern).join("\n") + "\n" });
  if (res.code !== 0) return fail("sparse-checkout", res.stderr);
  res = await git(["checkout", "-q"], { cwd: target, timeoutMs: 600_000 });
  if (res.code !== 0) return fail("checkout", res.stderr);
  return { ...base, status: "ok", files: selection.files.length };
}

const exists = (path: string) => stat(path).then(() => true, () => false);
let done = 0;
const counts = { ok: 0, empty: 0, error: 0, cached: 0 };
await pool(list, Number(values.concurrency), async ({ repo }) => {
  const metaPath = join(p.meta, `${repoDirName(repo)}.json`);
  if (!values.refetch && (await exists(metaPath))) {
    const prev = await readJson<FetchMeta>(metaPath);
    if (prev.status !== "error") {
      counts.cached++;
      done++;
      return;
    }
  }
  const meta = await fetchRepo(repo);
  await writeJson(metaPath, meta);
  counts[meta.status]++;
  done++;
  const detail = meta.status === "ok" ? `${meta.files} files` : meta.status === "error" ? meta.error : "no agent files";
  console.error(`[${done}/${list.length}] ${repo}: ${meta.status} (${detail})`);
});
console.error(`done: ${JSON.stringify(counts)}`);
