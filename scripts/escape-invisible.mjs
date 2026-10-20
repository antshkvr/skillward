// Replaces raw invisible/format characters in .ts sources with \u escapes.
// Some editors and tools silently turn escapes into the real characters;
// test/source-hygiene.test.ts catches that and `npm run fix:invisible` fixes it.
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const INVISIBLE =
  /[\p{Cf}\p{Zl}\p{Zp}\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000\u034F\u115F\u1160\u17B4\u17B5\u180B-\u180F\u3164\uFE00-\uFE0F\uFFA0\uFFF0-\uFFFB\u{e0100}-\u{e01ef}]|[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/gu;

const esc = (ch) => {
  const cp = ch.codePointAt(0);
  return cp > 0xffff ? `\\u{${cp.toString(16).toUpperCase()}}` : `\\u${cp.toString(16).toUpperCase().padStart(4, "0")}`;
};

const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (name === "fixtures" || name === "node_modules") return [];
    return statSync(p).isDirectory() ? walk(p) : /\.(ts|mjs)$/.test(p) ? [p] : [];
  });

for (const root of process.argv.slice(2)) {
  for (const file of walk(root)) {
    const text = readFileSync(file, "utf8");
    const lines = [];
    const fixed = text.replace(INVISIBLE, (ch, offset) => {
      lines.push(`${esc(ch)}@${text.slice(0, offset).split("\n").length}`);
      return esc(ch);
    });
    if (fixed !== text) {
      writeFileSync(file, fixed, "utf8");
      console.log(file, lines.join(" "));
    }
  }
}
