import { createColors } from "picocolors";
import { meetsThreshold } from "../engine/index.js";
import { escapeInvisible } from "../text.js";
import { SEVERITIES, type Finding, type Severity } from "../types.js";
import type { Reporter } from "./types.js";

export const textReporter: Reporter = ({ result, failOn, color }) => {
  const c = createColors(color);
  const paint: Record<Severity, (s: string) => string> = {
    high: (s) => c.bold(c.red(s)),
    medium: c.yellow,
    low: c.cyan,
    info: c.dim,
  };
  const out: string[] = [];

  const byFile = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const list = byFile.get(f.file);
    if (list) list.push(f);
    else byFile.set(f.file, [f]);
  }

  for (const [file, findings] of byFile) {
    out.push(c.underline(escapeInvisible(file)));
    for (const f of findings) {
      const pos = `${f.line}:${f.column ?? 1}`.padEnd(8);
      const sev = paint[f.severity](f.severity.padEnd(6));
      const rule = c.dim(`${f.ruleId}`);
      const conf = f.confidence === "high" ? "" : c.dim(` (confidence: ${f.confidence})`);
      out.push(`  ${pos}${sev} ${rule}  ${escapeInvisible(f.message)}${conf}`);
      if (f.snippet) out.push(`  ${" ".repeat(8)}${c.dim("│ " + f.snippet)}`);
    }
    out.push("");
  }

  if (result.suppressed.length) {
    // Shown on purpose: a malicious skill can add skillward-ignore comments too.
    out.push(c.yellow(`${result.suppressed.length} finding(s) suppressed by inline skillward-ignore:`));
    for (const f of result.suppressed) {
      const reason = f.suppression.reason ? escapeInvisible(f.suppression.reason) : "no reason given";
      out.push(c.dim(`  ${escapeInvisible(f.file)}:${f.line}  ${f.ruleId} ${f.severity}  (${reason}; directive on line ${f.suppression.line})`));
    }
    out.push("");
  }
  for (const s of result.skipped) out.push(c.dim(`skipped ${escapeInvisible(s.path)}: ${s.reason}`));
  for (const e of result.errors) {
    out.push(c.red(`error ${e.ruleId ? `in ${e.ruleId} ` : ""}on ${escapeInvisible(e.path)}: ${e.message}`));
  }
  if (result.skipped.length || result.errors.length) out.push("");

  const files = result.targets.reduce((n, t) => n + t.files.length, 0);
  const scanned = `${result.targets.length} target(s), ${files} file(s) scanned`;
  if (result.findings.length === 0) {
    out.push(c.green(`✔ No findings. ${scanned}.`));
  } else {
    const counts = [...SEVERITIES]
      .reverse()
      .map((s) => [s, result.findings.filter((f) => f.severity === s).length] as const)
      .filter(([, n]) => n > 0)
      .map(([s, n]) => paint[s](`${n} ${s}`))
      .join(", ");
    const failing = result.findings.filter((f) => meetsThreshold(f.severity, failOn)).length;
    const verdict = failing > 0 ? c.red(`✖ ${failing} at or above --fail-on ${failOn}`) : c.green(`below --fail-on ${failOn}`);
    out.push(`${result.findings.length} finding(s): ${counts}. ${scanned}. ${verdict}.`);
  }
  return out.join("\n") + "\n";
};
