import { member } from "../parsers/json-tree.js";
import type { Finding, ParsedFile, Rule } from "../types.js";
import { findingAt } from "./helpers.js";
import { mcpServers, redactSecrets, stringValue } from "./json-config.js";

const AUTH_HEADER = /authorization|token|api[_-]?key|secret|cookie|auth/i;
const SECRET_QUERY = /(?:^|[?&])[\w-]*(?:token|key|secret|auth|password|sig)[\w-]*=/i;
const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1|0\.0\.0\.0)$/i;
const TEMPLATED_URL = /^\$\{(\w+)(?::?-([^}]*))?\}$/;

const rule: Rule = {
  id: "SW012",
  name: "remote-mcp",
  severity: "low",
  appliesTo: ["mcp-config", "settings", "plugin-manifest"],
  description:
    "Inventory of MCP servers reached over the network (`url`, type http/sse): which hosts get your tool calls. Plain http:// to a non-local host, or credentials in the URL, raise it to medium.",
  check(target) {
    return target.files.flatMap((file) => (file.type === "json" ? checkFile(file) : []));
  },
};

export default rule;

function checkFile(file: ParsedFile): Finding[] {
  const findings: Finding[] = [];
  for (const server of mcpServers(file)) {
    const urlNode = member(server.config, "url");
    const raw = stringValue(urlNode);
    // An empty `url` is a placeholder the user fills in (plugin templates); nothing is contacted.
    if (!urlNode || raw === undefined || raw.trim() === "") continue;

    // `${VAR}` / `${VAR:-https://default}`: the host comes from the environment, or from the default.
    const template = TEMPLATED_URL.exec(raw.trim());
    let url: URL | undefined;
    try {
      url = new URL(template ? (template[2] ?? "") : raw); // Parsing only; nothing is fetched.
    } catch {
      url = undefined;
    }
    // A server on this machine is not remote.
    if (url && LOOPBACK.test(url.hostname)) continue;
    const host = template
      ? `a URL from $${template[1]}${url ? ` (default ${url.host})` : ""}`
      : (url?.host ?? "an unparseable URL");
    const where = server.project ? ` (project ${server.project})` : "";

    const headers = member(server.config, "headers");
    const authHeaders = headers?.kind === "object" ? headers.entries.map((e) => e.key).filter((k) => AUTH_HEADER.test(k)) : [];
    const notes: string[] = [];
    if (authHeaders.length > 0) notes.push(`sends ${authHeaders.join(", ")} header(s)`);

    let severity: Finding["severity"] = "low";
    if (url && url.protocol === "http:" && !LOOPBACK.test(url.hostname)) {
      severity = "medium";
      notes.push("unencrypted http:// — use https");
    }
    if (url && (url.username || url.password || SECRET_QUERY.test(url.search))) {
      severity = "medium";
      notes.push("credentials in the URL — move them to headers or env");
    }

    const finding = findingAt(rule, file, {
      offset: urlNode.start,
      length: urlNode.end - urlNode.start,
      severity,
      confidence: "high",
      message:
        `Remote MCP server "${server.name}"${where} → ${host}. Tool calls and their data go to this host` +
        (notes.length ? `; ${notes.join("; ")}` : "") +
        ". Make sure you trust it.",
    });
    findings.push({ ...finding, snippet: redactSecrets(redactUrlQuery(finding.snippet)) });
  }
  return findings;
}

/** Masks every query parameter value in URLs inside a snippet. */
function redactUrlQuery(text: string): string {
  return text.replace(/(https?:\/\/[^\s"'?]*\?)([^\s"']*)/gi, (_, base: string, query: string) => base + query.replace(/=([^&]*)/g, "=***"));
}
