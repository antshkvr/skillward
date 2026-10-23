// Fetch and scan in one pass, for a full run on a separate machine: each repository is fetched, scanned and its
// result written, then its checkout is removed unless it has a finding to review (`--keep`), so disk use stays small.
// Resumable: a repository with metadata (and a result, if it had agent files) is skipped. Write the summary
// afterwards with `npm run corpus:scan -- --dir <same dir>`.
//   npx tsx scripts/corpus/pipeline.ts --dir ~/corpus [--concurrency 4] [--keep high] [--limit 10]
import { rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { SEVERITIES, isSeverity, type Severity } from "../../src/types.js";
import { corpusArgs, paths, readJson, writeJson } from "./common.js";
import { fetchRepo, type FetchMeta } from "./fetch-repo.js";
import { pool, repoDirName, type Candidate } from "./lib.js";
import { scanCheckout } from "./scan-repo.js";

const { dir, values } = corpusArgs({
  concurrency: { type: "string", default: "4" },
  "max-files": { type: "string", default: "25000" },
  // Keep the checkout when a finding is at least this severe ("none" keeps nothing, "all" everything).
  keep: { type: "string", default: "high" },
  refetch: { type: "boolean", default: false },
  limit: { type: "string" },
});
const p = paths(dir);
const keep = values.keep as string;
if (keep !== "none" && keep !== "all" && !isSeverity(keep)) throw new Error(`--keep must be none, all or a severity, got ${keep}`);
const { candidates } = await readJson<{ candidates: Candidate[] }>(p.candidates);
const list = values.limit ? candidates.slice(0, Number(values.limit)) : candidates;
const maxFiles = Number(values["max-files"]);

const exists = (path: string) => stat(path).then(() => true, () => false);
const shouldKeep = (severities: Severity[]) =>
  keep === "all" || (keep !== "none" && severities.some((s) => SEVERITIES.indexOf(s) >= SEVERITIES.indexOf(keep as Severity)));

let done = 0;
const counts = { ok: 0, empty: 0, error: 0, cached: 0, kept: 0 };
const started = Date.now();
await pool(list, Number(values.concurrency), async ({ repo }) => {
  const name = repoDirName(repo);
  const metaPath = join(p.meta, `${name}.json`);
  const resultPath = join(p.results, `${name}.json`);
  if (!values.refetch && (await exists(metaPath))) {
    const prev = await readJson<FetchMeta>(metaPath);
    if (prev.status === "empty" || (prev.status === "ok" && (await exists(resultPath)))) {
      counts.cached++;
      done++;
      return;
    }
  }
  const checkout = join(p.checkouts, name);
  let meta = await fetchRepo(repo, checkout, { maxFiles });
  let detail = meta.status === "error" ? meta.error : "no agent files";
  const report = meta.status === "ok" ? await scanCheckout(checkout, meta).catch((err: Error) => err) : undefined;
  if (report instanceof Error) {
    await rm(checkout, { recursive: true, force: true });
    meta = { ...meta, status: "error", error: `scan: ${report.message}` };
    detail = meta.error;
  } else if (report) {
    // The result goes first: metadata without a result means "not done" on resume.
    await writeJson(resultPath, report);
    const kept = shouldKeep(report.findings.map((f) => f.severity));
    if (kept) counts.kept++;
    else await rm(checkout, { recursive: true, force: true });
    detail = `${meta.files} files${meta.hookScripts ? ` (${meta.hookScripts} hook scripts)` : ""}${meta.truncated ? `, ${meta.truncated} over the cap` : ""}, ${report.findings.length} findings, ${report.scanMs} ms${kept ? ", kept" : ""}`;
  }
  await writeJson(metaPath, meta);
  counts[meta.status]++;
  done++;
  const minutes = ((Date.now() - started) / 60_000).toFixed(1);
  console.error(`[${done}/${list.length} ${minutes} min] ${repo}: ${meta.status} (${detail})`);
});
console.error(`done: ${JSON.stringify(counts)}`);
