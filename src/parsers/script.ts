const BY_EXTENSION: Record<string, string> = {
  ".sh": "shell",
  ".bash": "shell",
  ".zsh": "shell",
  ".fish": "shell",
  ".command": "shell",
  ".ps1": "powershell",
  ".psm1": "powershell",
  ".bat": "batch",
  ".cmd": "batch",
  ".py": "python",
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".rb": "ruby",
  ".pl": "perl",
  ".php": "php",
  ".lua": "lua",
  ".go": "go",
  ".rs": "rust",
};

const BY_INTERPRETER: Array<[RegExp, string]> = [
  [/^(ba|z|da|k|fi)?sh$/, "shell"],
  [/^pwsh$|^powershell/, "powershell"],
  [/^python[\d.]*$/, "python"],
  [/^(node|deno|bun)$/, "javascript"],
  [/^(tsx|ts-node)$/, "typescript"],
  [/^ruby$/, "ruby"],
  [/^perl$/, "perl"],
  [/^php$/, "php"],
];

/** Script language from extension, falling back to the shebang. Returns undefined for non-scripts. */
export function detectScriptLanguage(fileName: string, text: string): string | undefined {
  const dot = fileName.lastIndexOf(".");
  if (dot > 0) {
    const lang = BY_EXTENSION[fileName.slice(dot).toLowerCase()];
    if (lang) return lang;
  }
  const shebang = /^#!([^\r\n]*)/.exec(text);
  if (!shebang) return undefined;
  const tokens = shebang[1]!.trim().split(/\s+/);
  let interpreter = (tokens[0] ?? "").split("/").pop()!;
  // `#!/usr/bin/env -S VAR=1 python3 -u` → python3
  if (interpreter === "env") interpreter = tokens.slice(1).find((t) => !t.startsWith("-") && !t.includes("=")) ?? "";
  for (const [re, lang] of BY_INTERPRETER) if (re.test(interpreter)) return lang;
  return "unknown";
}
