// Times each rule on one checked-out corpus repo, to find slow regexes on real data.
//   npx tsx scripts/corpus/profile.ts --repo owner/name
import { join } from "node:path";
import type { Config } from "../../src/config/index.js";
import { discover } from "../../src/discovery/index.js";
import { scan } from "../../src/engine/index.js";
import { parseFile } from "../../src/parsers/index.js";
import { ALL_RULES } from "../../src/rules/index.js";
import { corpusArgs, paths } from "./common.js";
import { repoDirName } from "./lib.js";

const { dir, values } = corpusArgs({ repo: { type: "string" }, rule: { type: "string" } });
if (!values.repo) throw new Error("--repo owner/name is required");
const root = join(paths(dir).checkouts, repoDirName(values.repo as string));
const config: Config = { ignore: [], rules: {}, inlineIgnore: false };

let started = Date.now();
await scan({ path: root, config, rules: [] });
console.log(`discovery + parsing: ${Date.now() - started} ms`);
for (const rule of ALL_RULES) {
  started = Date.now();
  const result = await scan({ path: root, config, rules: [rule] });
  console.log(`${rule.id}: ${Date.now() - started} ms (${result.findings.length} findings)`);
}

// `--rule SW003`: time that rule per file and show the slowest files.
const one = ALL_RULES.find((r) => r.id === values.rule);
if (one) {
  const times: Array<[number, string]> = [];
  for (const target of (await discover({ path: root })).targets) {
    for (const source of target.files) {
      const parsed = await parseFile(source);
      if (!parsed.ok) continue;
      const t = Date.now();
      one.check({ ...target, files: [parsed.file] });
      times.push([Date.now() - t, `${source.path} (${parsed.file.text.length} chars)`]);
    }
  }
  for (const [ms, path] of times.sort((a, b) => b[0] - a[0]).slice(0, 8)) console.log(`  ${ms} ms  ${path}`);
}
