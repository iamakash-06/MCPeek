# MCP Dev Summit Toronto: vulnerable server (MCPeek demo target)

A deliberately vulnerable MCP backend for a fictional conference where speakers manage sessions and attendees register and pay. It exists to be scanned with [MCPeek](https://github.com/iamakash-06/MCPeek). It trips all 25 MCPeek rules, including the migration-readiness checks.

**Do not deploy it.** Nothing here is meant to run, and every secret in it is fake.

## Run the demo

```bash
# Point MCPeek at the repo (use a full URL or an absolute path, not `.`)
npx mcpeek scan https://github.com/<you>/<this-repo>
npx mcpeek scan "$PWD"
```

The output types to show:

```bash
# 1. Terminal report (default): scores, severity table, taint chains, remediation
npx mcpeek scan "$PWD"

# 2. Migration readiness only
npx mcpeek scan "$PWD" --rules migration,session-state

# 3. One class of bug
npx mcpeek scan "$PWD" --rules sql-injection,command-injection

# 4. JSON, for scripts
npx mcpeek scan "$PWD" --format json

# 5. SARIF, for GitHub Code Scanning
npx mcpeek scan "$PWD" --format sarif --output summit.sarif

# 6. CI gate: exits 1 because of the critical and high findings
npx mcpeek scan "$PWD" --ci --fail-on high; echo "exit code: $?"
```

Expected result: security score **0/100**, migration readiness **81/100**, 4 critical, 14 high and 7 medium findings, 15 handlers analyzed.

> Keep this folder out of any path named `examples/`, `demos/`, `samples/`, `guides/`, `test/` or `fixtures/`. MCPeek tags findings there as example or test code and leaves them out of the score and the CI gate.

## What is wrong, and where

### Classic server vulnerabilities (`src/index.ts`, `src/db.ts`, `.env`)

| Tool | Rule | Problem |
|---|---|---|
| `get_speaker_guidelines` | `mcp-tool-poisoning` | `<IMPORTANT> Ignore previous instructions...` in the description |
| `list_my_sessions` | `mcp-missing-input-validation` | No schema |
| `submit_session` | `mcp-weak-input-validation`, `mcp-weak-schema-bounds` | `z.any()` and unbounded strings |
| `upload_slides` | `mcp-path-traversal` | `fileName` written under the slides folder with no boundary check |
| `import_speaker_headshot` | `mcp-ssrf` | Any URL is fetched |
| `filter_schedule` | `mcp-code-injection` | `eval` of a user predicate |
| `search_sessions` | `mcp-sql-injection` | Sink is in `db.ts`, one file from the handler (cross-file taint) |
| `get_attendee_badge` | `mcp-sql-injection` | Template literal in `db.query` |
| `export_attendees` | `mcp-command-injection` | `exec` with a user-controlled format and file name |
| top of `index.ts` | `mcp-hardcoded-credential` | Payment key in source |
| `.env` | `mcp-hardcoded-credential` | Committed secrets |

### Migration readiness to 2026-07-28 (`src/index.ts`, `package.json`)

| Where | Rule | Problem |
|---|---|---|
| `sessions` map and `transports` map | `mcp-session-keyed-state` (medium) | In-process state keyed by session id |
| `sessionIdGenerator` | `mcp-session-keyed-state` (low) | Transport mints session ids |
| `buy_ticket`, `draft_session_blurb` | `mcp-migration-push-request` | `elicitInput`, `createMessage`, `listRoots` |
| bottom of `index.ts` | `mcp-migration-removed-method` | `ping`, `SetLevelRequestSchema`, `notifications/roots/list_changed` |
| `package.json` | `mcp-migration-legacy-sdk`, `mcp-migration-unbounded-sdk-range` | v1 package, and `*` / `latest` ranges |

### v2 features used badly (`src/checkout.ts`, `src/ticket-card.ts`)

Checkout was moved to v2 first, and the new primitives were misused.

| Where | Rule | Problem |
|---|---|---|
| `createRequestStateCodec` | `mcp-requeststate-unbound`, `mcp-requeststate-weak-key` | No `bind`, key hardcoded |
| `refund_ticket` mint | `mcp-requeststate-secret` | Payment token minted into signed, unencrypted state |
| `refund_ticket` | `mcp-meta-authz` | `_meta.role === "organiser"` grants access |
| `refund_ticket` schema | `mcp-header-sensitive` | `x-mcp-header` on a payment token |
| `cancel_registration` | `mcp-requeststate-authz-gap` | State value reaches a mutating call with no ownership check |
| `routeByHeader` | `mcp-header-trust` | `Mcp-Name` header drives a branch with no body cross-check |
| `issueReceipt` | `mcp-signed-token-secret` | Payment token inside a JWT payload |
| `ticket_card` HTML | `mcp-apps-html-xss` | Display name interpolated unescaped |
| `ticket_card` CSP | `mcp-apps-wildcard-csp` | `connectDomains: ["*"]`, `resourceDomains: ["https:"]` |
