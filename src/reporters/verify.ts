import { createColors } from "picocolors";
import type { ScanResult } from "../engine/index.js";
import type { VerifyResult } from "../lock/index.js";
import { escapeInvisible } from "../text.js";
import type { Severity } from "../types.js";
import { VERSION } from "../version.js";
import { jsonReport } from "./json.js";
import { textReporter } from "./text.js";

export interface VerifyReportContext {
  verify: VerifyResult;
  /** Scan of added and changed files; absent when nothing changed. */
  scan?: ScanResult;
  failOn: Severity;
  color: boolean;
}

export const VERIFY_REPORT_VERSION = 1;

export function verifyText({ verify, scan, failOn, color }: VerifyReportContext): string {
  const c = createColors(color);
  const out: string[] = [];
  const count = (s: string) => verify.changes.filter((ch) => ch.status === s).length;

  if (verify.changes.length === 0) {
    out.push(c.green(`✔ Matches ${verify.lockName}.`));
    return out.join("\n") + "\n";
  }

  out.push(
    `${verify.lockName}: ${count("changed")} changed, ${count("added")} added, ${count("removed")} removed file(s)` +
      (verify.targetsAdded.length ? `; new target(s): ${verify.targetsAdded.map(escapeInvisible).join(", ")}` : "") +
      (verify.targetsRemoved.length ? `; removed target(s): ${verify.targetsRemoved.map(escapeInvisible).join(", ")}` : ""),
    "",
  );
  const mark = { changed: c.yellow("M"), added: c.green("A"), removed: c.red("D") };
  for (const ch of verify.changes) {
    out.push(`  ${mark[ch.status]} ${escapeInvisible(ch.path)}${ch.note ? c.dim(`  (${ch.note})`) : ""}`);
    if (ch.diff) {
      for (const line of ch.diff.split("\n")) {
        const painted = line.startsWith("+") ? c.green(line) : line.startsWith("-") ? c.red(line) : line.startsWith("@@") ? c.cyan(line) : c.dim(line);
        out.push(`      ${painted}`);
      }
    }
  }
  out.push("");
  if (scan) {
    out.push(c.bold("Scan of added and changed files:"), textReporter({ result: scan, failOn, color }));
  }
  out.push(c.dim(`Review the changes, then run \`${verify.relock}\` to accept them.`));
  return out.join("\n") + "\n";
}

export function verifyJson({ verify, scan, failOn }: VerifyReportContext): string {
  const report = {
    version: VERIFY_REPORT_VERSION,
    tool: { name: "skillward", version: VERSION },
    lockfile: verify.lockPath,
    clean: verify.changes.length === 0,
    targets: { added: verify.targetsAdded, removed: verify.targetsRemoved },
    // Absolute paths stay internal; the report uses display paths.
    changes: verify.changes.map(({ absPath: _absPath, ...rest }) => rest),
    scan: scan ? jsonReport({ result: scan, failOn, color: false }) : null,
  };
  return JSON.stringify(report, null, 2) + "\n";
}
