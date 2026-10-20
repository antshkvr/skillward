import type { Finding, ParsedFile, Rule } from "../types.js";

/**
 * A hook runs automatically, so the script it runs is part of what you agree to. A readable script is checked by the
 * other rules (discovery adds it to the target); this rule reports the ones nobody can review: obfuscated, packed,
 * binary, huge or minified.
 */
const LARGE_BYTES = 1024 * 1024;
const LONG_LINE = 20_000;

const rule: Rule = {
  id: "SW017",
  name: "hook-script",
  severity: "high",
  appliesTo: ["settings", "plugin-manifest"],
  description:
    "A hook runs a script that can't be reviewed: obfuscated (javascript-obfuscator, packers, escape-encoded strings), a binary, over 1 MB, or minified into very long lines. Hooks run automatically, so this is code you run without reading.",
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

function checkFile(file: ParsedFile): Finding[] {
  const info = file.hookScript;
  if (!info || !file.hookTarget) return [];
  const when = `Hook on ${file.hookTarget.events.join(", ")} (${file.hookTarget.from}) runs ${file.path}`;
  const size = formatSize(info.size);
  let severity: Finding["severity"];
  let why: string;
  if (info.binary) {
    severity = "high";
    why = `a ${size} binary`;
  } else if (info.signals.length) {
    severity = "high";
    why = `${size} with ${info.signals.join(", ")}`;
  } else if (info.size > LARGE_BYTES || info.maxLineLength > LONG_LINE) {
    severity = "medium";
    why = info.maxLineLength > LONG_LINE ? `${size}, minified (a line of ${info.maxLineLength.toLocaleString("en-US")} characters)` : size;
  } else {
    return [];
  }
  const notScanned = info.contentScanned ? "" : info.binary ? " Its content can't be scanned." : " It is too large to scan.";
  return [
    {
      ruleId: rule.id,
      severity,
      file: file.path,
      line: 1,
      column: 1,
      message: `${when}: ${why}. It runs automatically and can't be reviewed — obfuscation and opaque bundles are how malicious hooks hide.${notScanned} Find out where it comes from; remove the hook if you don't need it.`,
      snippet: "",
      confidence: severity === "high" ? "high" : "medium",
    },
  ];
}

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} bytes`;
}
