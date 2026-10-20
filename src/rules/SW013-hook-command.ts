import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { findingAt } from "./helpers.js";
import { withVocab } from "./vocabulary.js";
import { frontmatterHookCommands, hookCommands, redactSecrets, shorten, type HookCommand } from "./json-config.js";
import { checkLine as secretAccess } from "./SW005-secret-path-access.js";

/** Network tools and remote URLs. `ssh` must not match inside `~/.ssh`. */
const NETWORK = withVocab(
  /(?<![\w./-])(?:curl|wget|nc|ncat|netcat|socat|telnet|ftp|sftp|scp|ssh|rsync|__psFetch__|__psBits__)(?![\w.-])|\/dev\/(?:tcp|udp)\/|\bhttps?:\/\/(?!(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$))/i,
);
const LOOPBACK_URL = /^https?:\/\/(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?:[:/]|$)/i;

/**
 * A hook that only starts a script shipped with the project, plugin or skill (`bash ${CLAUDE_PLUGIN_ROOT}/hooks/x.sh`,
 * `node .claude/hooks/guard.cjs`): what it does is in that script, which is scanned as part of the target when it
 * is in the repo. Inline shell (`sh -c …`, pipes, `$(…)`) is not local-only and stays medium.
 */
const LOCAL_SCRIPT = new RegExp(
  String.raw`^(?:\w+=(?:"[^"]*"|'[^']*'|[^\s"'$]*)\s+)*` + // env assignments
    String.raw`(?:cmd(?:\.exe)?\s+/[cC]\s+)?` +
    String.raw`(?:(?:bash|sh|zsh|node|python3?|py|ruby|perl|tsx|bun(?:\s+run)?|deno\s+run(?:\s+-\w+)*|npx\s+tsx|uv\s+run(?:\s+--?[\w-]+)*(?:\s+python3?)?|(?:pwsh|powershell)(?:\.exe)?(?:\s+-\w+(?:\s+(?:Bypass|Unrestricted|RemoteSigned))?)*)\s+)?` +
    String.raw`["']?(?:\$\{?CLAUDE_(?:PROJECT_DIR|PLUGIN_ROOT|SKILL_DIR)(?::-[^}]*)?\}?["']?[\\/]|\.{1,2}[\\/]|(?:\$HOME|\$\{HOME\}|~)[\\/]\.claude[\\/]|(?![/~$\\-])[\w.-]+[\\/])` +
    String.raw`[^\s"'|;&<>${"`"}()]*["']?` + // the script path
    String.raw`(?:\s+(?!-c\b|-e\b)[^\s|;&<>${"`"}()]+)*` + // plain arguments
    String.raw`(?:\s+2?>\s*/dev/null(?:\s+2>&1)?)?(?:\s*\|\|\s*(?:true|:|exit\s+0))?\s*$`,
  "i",
);

const rule: Rule = {
  id: "SW013",
  name: "hook-command",
  severity: "medium",
  appliesTo: ["settings", "plugin-manifest", "skill", "instructions"],
  description:
    "Hooks that run shell commands (settings, plugins, skill/agent frontmatter) and the status line command. Every hook is listed: a hook that only starts a script shipped with the project/plugin is low, other commands medium; network access or secret paths in the command raise it to high.",
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

function checkFile(file: ParsedFile): Finding[] {
  const hooks = file.type === "json" ? hookCommands(file) : file.type === "markdown" ? frontmatterHookCommands(file) : [];
  return hooks.map((hook) => {
    const { severity, confidence, why } = assess(hook);
    const trigger =
      hook.event === "statusLine" ? "Status line runs" : `Hook on ${hook.event}${hook.matcher ? ` (matcher "${hook.matcher}")` : ""} ${hook.type === "url" ? "posts to" : "runs"}`;
    const finding = findingAt(rule, file, {
      offset: hook.offset,
      length: Math.min(hook.value.length + 2, 200),
      severity,
      confidence,
      message: `${trigger}: ${redactSecrets(shorten(hook.value))}. ${why}`,
    });
    return { ...finding, snippet: redactSecrets(finding.snippet) };
  });
}

function assess(hook: HookCommand): { severity: Severity; confidence: Confidence; why: string } {
  if (hook.type === "url") {
    return LOOPBACK_URL.test(hook.value)
      ? { severity: "medium", confidence: "high", why: "Hook event data (tool inputs, prompts) is sent to a local server." }
      : { severity: "high", confidence: "high", why: "Hook event data (tool inputs, prompts) leaves the machine. Make sure you trust this endpoint." };
  }
  if (NETWORK.test(hook.value)) {
    return { severity: "high", confidence: "high", why: "It reaches the network automatically, without asking. Review it or remove it." };
  }
  if (secretAccess(hook.value).some((h) => h.severity !== "info")) {
    return { severity: "high", confidence: "high", why: "It touches credential files automatically, without asking. Review it or remove it." };
  }
  if (hook.event === "statusLine") {
    return { severity: "info", confidence: "high", why: "Runs constantly while the session is open; make sure you know what it does." };
  }
  if (LOCAL_SCRIPT.test(hook.value.trim())) {
    return {
      severity: "low",
      confidence: "high",
      why: "Runs a script that ships with the project/plugin automatically; review that script (it is scanned when it is part of this target).",
    };
  }
  return { severity: "medium", confidence: "high", why: "Runs automatically, without asking; make sure you know what it does." };
}
