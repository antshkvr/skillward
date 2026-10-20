// Release gate: the pushed tag, package.json, the action's default version and the changelog must agree.
//   node scripts/check-release.mjs v0.1.1
import { readFileSync } from "node:fs";

const tag = process.argv[2] ?? "";
const pkg = JSON.parse(readFileSync("package.json", "utf8"));
const action = readFileSync("action.yml", "utf8");
const changelog = readFileSync("CHANGELOG.md", "utf8");

const problems = [];
if (tag !== `v${pkg.version}`) problems.push(`tag "${tag}" does not match package.json version ${pkg.version} (expected v${pkg.version})`);
const actionDefault = /^\s{2}version:\s*\n(?:\s{4}.*\n)*?\s{4}default:\s*"([^"]+)"/m.exec(action)?.[1];
if (actionDefault !== pkg.version) problems.push(`action.yml default version is ${actionDefault ?? "missing"}, expected ${pkg.version}`);
if (!new RegExp(`^## ${pkg.version.replace(/\./g, "\\.")}(?:\\s|$)`, "m").test(changelog)) {
  problems.push(`CHANGELOG.md has no "## ${pkg.version}" section`);
}

if (problems.length) {
  for (const p of problems) console.error(`release check: ${p}`);
  process.exit(1);
}
console.log(`release check: v${pkg.version} OK`);
