import type { HookScriptInfo } from "../types.js";

/** Signals that a script was made unreadable on purpose. Each is cheap and linear on the whole text. */
const SIGNALS: Array<{ label: string; test: (text: string) => boolean }> = [
  { label: "javascript-obfuscator identifiers (_0x…)", test: (t) => count(t, /\b_0x[0-9a-f]{4,6}\b/g, 20) },
  { label: "a packer (eval(function(p,a,c,k,e,…)))", test: (t) => /eval\(function\(p,a,c,k,e,[rd]\)/.test(t) },
  { label: "dense \\xNN escapes", test: (t) => count(t, /\\x[0-9a-fA-F]{2}/g, 300) },
  { label: "String.fromCharCode chains", test: (t) => count(t, /String\.fromCharCode\s*\(/g, 20) },
  { label: "a long base64 string run at load time", test: (t) => /(?:atob|b64decode|Buffer\.from)\s*\(\s*["'`][A-Za-z0-9+/=]{2000,}/.test(t) },
];

function count(text: string, re: RegExp, atLeast: number): boolean {
  re.lastIndex = 0;
  let n = 0;
  while (re.exec(text)) if (++n >= atLeast) return true;
  return false;
}

/** Size, shape and obfuscation signals of a script, from its raw bytes. Nothing is executed. */
export function describeScript(buffer: Buffer, binary: boolean, contentScanned: boolean): HookScriptInfo {
  let lines = 1;
  let maxLineLength = 0;
  let current = 0;
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] === 0x0a) {
      lines++;
      if (current > maxLineLength) maxLineLength = current;
      current = 0;
    } else current++;
  }
  if (current > maxLineLength) maxLineLength = current;
  const signals = binary ? [] : SIGNALS.filter((s) => s.test(buffer.toString("utf8"))).map((s) => s.label);
  return { size: buffer.length, lines, maxLineLength, binary, signals, contentScanned };
}
