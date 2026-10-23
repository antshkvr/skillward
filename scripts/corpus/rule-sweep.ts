// Runs one rule over the whole fetched corpus (not only files it flagged before) — for measuring a new rule.
// Resumable: per-repo results go to <corpus>/sweeps/<rule>/; rerun to continue, `--report` to summarize.
//   npx tsx scripts/corpus/rule-sweep.ts --rule SW016 [--shard 1/2] [--concurrency 2]
//   npx tsx scripts/corpus/rule-sweep.ts --rule SW016 --report [--severity high] [--samples 15]
import { mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../../src/config/index.js";
import { scan } from "../../src/engine/index.js";
import { ALL_RULES } from "../../src/rules/index.js";
import { SEVERITIES, type Finding, type Severity } from "../../src/types.js";
import { corpusArgs, paths, readJson, writeJson } from "./common.js";
import type { FetchMeta } from "./fetch-repo.js";
import { pool, repoDirName } from "./lib.js";

const { dir, values } = corpusArgs({
  rule: { type: "string" },
  shard: { type: "string" },
  report: { type: "boolean", default: false },
  severity: { type: "string", default: "*" },
  samples: { type: "string", default: "12" },
  concurrency: { type: "string", default: "2" },
});
const rule = ALL_RULES.find((r) => r.id === values.rule);
if (!rule) throw new Error(`--rule must be one of ${ALL_RULES.map((r) => r.id).join(", ")}`);
const AUDIT_CONFIG: Config = { ignore: [], rules: {}, inlineIgnore: false };
const p = paths(dir);
const out = join(dir, "sweeps", rule.id);
await mkdir(out, { recursive: true });

interface SweepResult {
  repo: string;
  sha?: string;
  findings: Finding[];
}

if (!values.report) {
  const metas = await Promise.all((await readdir(p.meta)).filter((f) => f.endsWith(".json")).map((f) => readJson<FetchMeta>(join(p.meta, f))));
  const shard = values.shard ? (values.shard as string).split("/").map(Number) : undefined;
  const done = new Set(await readdir(out));
  const repos = metas
    .filter((m) => m.status === "ok")
    .sort((a, b) => (a.repo < b.repo ? -1 : 1))
    .filter((_, i) => !shard || i % shard[1]! === shard[0]! - 1)
    .filter((m) => !done.has(`${repoDirName(m.repo)}.json`));
  let n = 0;
  await pool(repos, Number(values.concurrency), async (meta) => {
    const result = await scan({ path: join(p.checkouts, repoDirName(meta.repo)), config: AUDIT_CONFIG, rules: [rule] });
    await writeJson(join(out, `${repoDirName(meta.repo)}.json`), { repo: meta.repo, sha: meta.sha, findings: result.findings } satisfies SweepResult);
    if (++n % 100 === 0) console.error(`${n}/${repos.length}`);
  });
  console.error(`swept ${n} repos (${done.size} already done)`);
} else {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  const reposHit = new Set<string>();
  const groups = new Map<string, { n: number; repos: Set<string>; ex: string[] }>();
  const files = await readdir(out);
  for (const f of files) {
    const r = await readJson<SweepResult>(join(out, f));
    for (const x of r.findings) {
      counts[x.severity]++;
      reposHit.add(r.repo);
      if (values.severity !== "*" && x.severity !== values.severity) continue;
      const key = `${x.severity}/${x.confidence} ${x.message.slice(0, 70)}`;
      const g = groups.get(key) ?? { n: 0, repos: new Set(), ex: [] };
      g.n++;
      g.repos.add(r.repo);
      if (g.ex.length < 300) g.ex.push(`${r.repo}:${x.file}:${x.line}  ${x.snippet}`);
      groups.set(key, g);
    }
  }
  console.log(`${rule.id} over ${files.length} repos: ${SEVERITIES.map((s) => `${s} ${counts[s]}`).join(", ")}; repos with findings: ${reposHit.size}`);
  const n = Number(values.samples);
  for (const [key, g] of [...groups].sort((a, b) => b[1].n - a[1].n).slice(0, 15)) {
    console.log(`\n### ${g.n} (${g.repos.size} repos) ${key}`);
    const step = Math.max(1, Math.floor(g.ex.length / n));
    for (let i = 0, shown = 0; i < g.ex.length && shown < n; i += step, shown++) console.log("  " + g.ex[i]!.slice(0, 220));
  }
}
