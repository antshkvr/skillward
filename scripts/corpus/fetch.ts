// Step 2: fetch the candidates (see fetch-repo.ts for what lands on disk). For a run that scans each repository right
// after fetching it and keeps only results, use pipeline.ts.
import { stat } from "node:fs/promises";
import { join } from "node:path";
import { corpusArgs, paths, readJson, writeJson } from "./common.js";
import { fetchRepo, type FetchMeta } from "./fetch-repo.js";
import { pool, repoDirName, type Candidate } from "./lib.js";

export type { FetchMeta } from "./fetch-repo.js";

const { dir, values } = corpusArgs({
  concurrency: { type: "string", default: "6" },
  "max-files": { type: "string", default: "25000" },
  refetch: { type: "boolean", default: false },
  limit: { type: "string" },
});
const p = paths(dir);
const { candidates } = await readJson<{ candidates: Candidate[] }>(p.candidates);
const list = values.limit ? candidates.slice(0, Number(values.limit)) : candidates;
const maxFiles = Number(values["max-files"]);

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
  const meta = await fetchRepo(repo, join(p.checkouts, repoDirName(repo)), { maxFiles });
  await writeJson(metaPath, meta);
  counts[meta.status]++;
  done++;
  const detail = meta.status === "ok" ? `${meta.files} files` : meta.status === "error" ? meta.error : "no agent files";
  console.error(`[${done}/${list.length}] ${repo}: ${meta.status} (${detail})`);
});
console.error(`done: ${JSON.stringify(counts)}`);
