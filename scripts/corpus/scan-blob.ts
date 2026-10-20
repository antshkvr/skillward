// Scans files straight from a corpus checkout's git objects, in memory, without writing them to disk.
// For files that antivirus removed from the working tree on checkout (they are the most interesting ones):
//   npx tsx scripts/corpus/scan-blob.ts --repo owner/name --file path/in/repo [--file …]
// Prints severities and rule ids only, never the content.
import { join } from "node:path";
import { classifyFile } from "../../src/discovery/index.js";
import { parseText } from "../../src/parsers/index.js";
import { ALL_RULES } from "../../src/rules/index.js";
import type { Finding, TargetKind } from "../../src/types.js";
import { corpusArgs, paths, run } from "./common.js";
import { repoDirName } from "./lib.js";

const { dir, values } = corpusArgs({ repo: { type: "string" }, file: { type: "string", multiple: true } });
const repo = values.repo as string | undefined;
const files = (values.file as string[] | undefined) ?? [];
if (!repo || !files.length) throw new Error("--repo owner/name and at least one --file are required");
const checkout = join(paths(dir).checkouts, repoDirName(repo));

for (const file of files) {
  const blob = await run("git", ["-c", "core.hooksPath=/dev/null", "cat-file", "-p", `HEAD:${file}`], { cwd: checkout });
  if (blob.code !== 0) {
    console.log(`${repo}:${file}: not in git objects (${blob.stderr.trim()})`);
    continue;
  }
  const kind: TargetKind = file.endsWith("SKILL.md") || file.includes("/skills/") ? "skill" : (classifyFile(`/r/${file}`, []) ?? "instructions");
  const parsed = parseText({ absPath: join(checkout, file), path: file }, blob.stdout);
  const findings: Finding[] = ALL_RULES.filter((r) => r.appliesTo.includes(kind)).flatMap((r) => r.check({ kind, path: file, files: [parsed] }));
  const bySeverity: Record<string, number> = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  const high = [...new Set(findings.filter((f) => f.severity === "high").map((f) => f.ruleId))].sort();
  console.log(`${repo}:${file} (${kind}, ${blob.stdout.length} chars): ${JSON.stringify(bySeverity)} high rules: ${high.join(", ") || "-"}`);
}
