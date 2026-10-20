import type { Rule } from "../types.js";
import SW001 from "./SW001-hidden-unicode.js";
import SW002 from "./SW002-html-comment-instructions.js";
import SW003 from "./SW003-encoded-payload.js";
import SW004 from "./SW004-pipe-to-shell.js";
import SW005 from "./SW005-secret-path-access.js";
import SW006 from "./SW006-env-dump.js";
import SW007 from "./SW007-suspicious-egress.js";
import SW008 from "./SW008-permission-bypass.js";
import SW009 from "./SW009-concealment.js";
import SW010 from "./SW010-fake-prerequisite.js";
import SW011 from "./SW011-unpinned-mcp.js";
import SW012 from "./SW012-remote-mcp.js";
import SW013 from "./SW013-hook-command.js";
import SW014 from "./SW014-persistence.js";
import SW015 from "./SW015-dangerous-script.js";

/** All built-in rules, in ID order. Rules are registered explicitly — nothing is loaded dynamically. */
export const ALL_RULES: Rule[] = [
  SW001,
  SW002,
  SW003,
  SW004,
  SW005,
  SW006,
  SW007,
  SW008,
  SW009,
  SW010,
  SW011,
  SW012,
  SW013,
  SW014,
  SW015,
];

export function findRule(id: string): Rule | undefined {
  return ALL_RULES.find((r) => r.id === id);
}
