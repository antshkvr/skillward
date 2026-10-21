import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/index.js";
import { lock, SNAPSHOT_DIR, verify } from "../src/lock/index.js";
import { redactSecrets } from "../src/rules/SW016-secret-in-config.js";

/** Token-shaped values are built at run time, never committed (see SW016.test.ts). */
function random(seed: string, length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  let block = seed;
  while (out.length < length) {
    block = createHash("sha256").update(block).digest("hex");
    for (let i = 0; i < block.length && out.length < length; i += 2) out += alphabet[parseInt(block.slice(i, i + 2), 16) % alphabet.length];
  }
  return out;
}
const github = "gh" + "p_" + random("redact-gh", 36);
const github2 = "gh" + "p_" + random("redact-gh2", 36);
const generic = "Qx7" + random("redact-generic", 29);
const jwt = "ey" + "J" + random("h", 20) + "." + random("p", 30) + "." + random("s", 30);

describe("redactSecrets", () => {
  it("keeps the first 4 characters and the length of provider tokens, secret assignments and JWTs", () => {
    const text = `{"env": {"GITHUB_TOKEN": "${github}", "DB_PASSWORD": "${generic}", "SESSION": "${jwt}"}, "max_tokens": "4096"}`;
    const masked = redactSecrets(text);
    for (const secret of [github, generic, jwt]) {
      expect(masked).not.toContain(secret);
      expect(masked).toContain(`${secret.slice(0, 4)}…[${secret.length} chars]`);
    }
    expect(masked).toContain('"max_tokens": "4096"');
  });

  it("masks private key blocks, even unterminated ones", () => {
    const body = random("pem", 64);
    expect(redactSecrets(`a\n-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----\nb`)).not.toContain(body);
    expect(redactSecrets(`-----BEGIN PRIVATE KEY-----\n${body}\n`)).not.toContain(body);
  });

  it("leaves ordinary text alone", () => {
    const text = "Run `npm test` and read https://example.invalid/docs before editing src/index.ts.\n";
    expect(redactSecrets(text)).toBe(text);
  });
});

describe("verify never prints or snapshots secrets", () => {
  function project(): string {
    const root = mkdtempSync(join(tmpdir(), "skillward-redact-"));
    mkdirSync(join(root, ".claude"), { recursive: true });
    writeFileSync(join(root, ".mcp.json"), JSON.stringify({ mcpServers: { gh: { command: "gh-mcp", env: { GITHUB_TOKEN: github } } } }, null, 2));
    return root;
  }

  it("masks secrets in snapshots and in diffs", async () => {
    const root = project();
    await lock({ root, config: DEFAULT_CONFIG });
    const dir = join(root, SNAPSHOT_DIR);
    for (const name of readdirSync(dir)) expect(readFileSync(join(dir, name), "utf8")).not.toContain(github);

    writeFileSync(join(root, ".mcp.json"), JSON.stringify({ mcpServers: { gh: { command: "gh-mcp-v2", env: { GITHUB_TOKEN: github2 } } } }, null, 2));
    const [change] = (await verify({ root, config: DEFAULT_CONFIG })).changes;
    expect(change!.diff).toContain("gh-mcp-v2");
    expect(change!.diff).not.toContain(github2);
    expect(change!.diff).not.toContain(github);
    expect(change!.diff).toContain(`${github2.slice(0, 4)}…[${github2.length} chars]`);
  });

  it("says when only a masked secret changed", async () => {
    const root = project();
    await lock({ root, config: DEFAULT_CONFIG });
    writeFileSync(join(root, ".mcp.json"), readFileSync(join(root, ".mcp.json"), "utf8").replace(github, github2));
    const [change] = (await verify({ root, config: DEFAULT_CONFIG })).changes;
    expect(change).toMatchObject({ status: "changed", note: "only masked secret values changed" });
    expect(change!.diff).toBeUndefined();
  });
});
