import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import rule from "../../src/rules/SW016-secret-in-config.js";
import { checkText } from "../helpers.js";

/**
 * Provider tokens are built at run time from a seed, so no token-shaped string is ever committed to the repository
 * (secret-scanning push protection would block it, and it would look like a leak).
 */
function random(seed: string, length: number, alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"): string {
  let out = "";
  let block = seed;
  while (out.length < length) {
    block = createHash("sha256").update(block).digest("hex");
    for (let i = 0; i < block.length && out.length < length; i += 2) out += alphabet[parseInt(block.slice(i, i + 2), 16) % alphabet.length];
  }
  return out;
}
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const tokens: Array<[string, string]> = [
  ["a GitHub token", "gh" + "p_" + random("gh", 36)],
  ["an AWS access key ID", "AK" + "IA" + random("aws", 16, UPPER)],
  ["a Slack token", "xo" + "xb-" + random("slack", 24, "0123456789") + "-" + random("slack2", 24)],
  ["an Anthropic API key", "sk-" + "ant-api03-" + random("ant", 80)],
  ["an OpenAI API key", "sk-" + "proj-" + random("oai", 48)],
  ["a Stripe live key", "sk" + "_live_" + random("stripe", 28)],
  ["a Google API key", "AI" + "za" + random("google", 35)],
  ["a Hugging Face token", "h" + "f_" + random("hf", 34)],
  ["a Slack webhook URL", "https://hooks.slack.com/services/T" + random("t", 9, UPPER) + "/B" + random("b", 10, UPPER) + "/" + random("w", 24)],
];

describe("SW016 secret-in-config", () => {
  it.each(tokens)("reports %s as high and never prints it in full", (label, value) => {
    const findings = checkText(rule, `{"permissions": {"allow": ["Bash(curl -H 'x: ${value}' https://example.invalid)"]}}`, ".claude/settings.local.json", "settings");
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SW016", severity: "high", confidence: "high" });
    expect(findings[0]!.message).toContain(label);
    expect(findings[0]!.snippet).not.toContain(value);
    expect(findings[0]!.snippet).toContain(`${value.slice(0, 4)}…[${value.length} chars]`);
  });

  it.each([
    [`{"env": {"OPENAI_API_KEY": "${random("k1", 40)}"}}`, ".mcp.json", "mcp-config"],
    [`export SERVICE_TOKEN=${random("k2", 32)}`, "scripts/run.sh", "skill"],
    [`mytool --api-key ${random("k3", 32)}`, "scripts/run.sh", "skill"],
    [`curl -H "Authorization: Bearer ${random("k4", 40)}" https://example.invalid`, "scripts/run.sh", "skill"],
  ] as const)("reports a secret-looking value for a secret-named key in config or code as medium: %s", (line, path, kind) => {
    const [f] = checkText(rule, line, path, kind);
    expect(f).toMatchObject({ severity: "medium", confidence: "medium" });
  });

  it("reports the same value in documentation as low (usually an example)", () => {
    expect(checkText(rule, `export SERVICE_TOKEN=${random("k2", 32)}`)[0]).toMatchObject({ severity: "low", confidence: "low" });
  });

  it("reports provider tokens in the scanned repo's test files as low", () => {
    const value = "gh" + "p_" + random("gh-test", 36);
    for (const path of ["tests/redact.test.ts", "src/__tests__/scan.ts", "test_secrets.py", "fixtures/leak/CLAUDE.md"]) {
      expect(checkText(rule, `TOKEN = "${value}"`, path, "skill")[0], path).toMatchObject({ severity: "low", confidence: "low" });
    }
  });

  it("stays linear on minified one-line bundles", () => {
    const bundle = "var a=" + random("min", 400_000) + ";const tokenizer=" + random("min2", 400_000) + ';x="' + "ab".repeat(100_000) + '";';
    const started = Date.now();
    checkText(rule, bundle, "main.js", "skill");
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it.each([
    '"OPENAI_API_KEY": "${OPENAI_API_KEY}"',
    '"api_key": "your-api-key-here"',
    "export GITHUB_TOKEN=$GITHUB_TOKEN",
    '"token": "FAKE_KEY_0123456789abcdef"',
    '"password": "<password>"',
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    '"secret_name": "production-database-credentials"',
    '"token_path": "/var/run/secrets/kubernetes.io/serviceaccount/token"',
    "Authorization: Bearer $TOKEN",
    '"api_key_env": "ANTHROPIC_API_KEY"',
    "Set GH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxx before running.",
    // Shapes found in public skills.
    '"API_KEY": "sk-1234567890abcdefgh"',
    '"password": "SecurePassword123!"',
    '{ "tokenAddress": "0x42d9a1c0b7e5f3a8c6d4e2f0a9b8c7d6e5f4a3b2" }',
    '"max_tokens": "4096"',
    '<img src="https://storage.example.invalid/o/logo.png?alt=media&token=c42d6e1f-9a3b-4c7d-8e5f-1a2b3c4d5e6f">',
    "TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz",
    '<img src="https://storage.example.invalid/o/a.png?alt=media&#x26;token=93c9e1f2-7a4b-4c3d-9e8f-0a1b2c3d4e5f">',
    '"hashed_secret": "1348b145fa1a555461c1b790a2f66614781091e9"',
    "--tokenizer-type GPT2BPETokenizer9",
    "this.nextMessageLength=-1,this.messageToken=0,this.callback=e;let n=new Uint32Array(this._binaryTokens)",
  ])("ignores placeholders, variables and names: %s", (line) => {
    expect(checkText(rule, line)).toEqual([]);
  });
});
