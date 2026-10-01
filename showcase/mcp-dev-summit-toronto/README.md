# MCP Dev Summit Toronto: MCPeek showcase

Two backends for the same fictional conference, built to show MCPeek end to end.

| | `vulnerable-v1/` | `clean-v2/` |
|---|---|---|
| Story | The rushed first build. v1 SDK, per-session carts, server-pushed prompts, and a half-finished move to v2. | The same product after migration and a security pass. |
| SDK | `@modelcontextprotocol/sdk` (`*`) plus `@modelcontextprotocol/server` (`latest`) | `@modelcontextprotocol/server` (`^2.0.0`) only |
| Security score | 0/100 | 100/100 |
| Migration score | 81/100 | 100/100 |
| `--ci` exit code | 1 | 0 |
| Rules fired | all 25 | none |

Both expose the same features, so you can diff them side by side:

- **Speakers** submit a session, upload slides, import a headshot, filter the schedule, and read the guidelines.
- **Attendees** search sessions, look up a badge, buy a ticket, and cancel a registration.
- **Organisers** export the attendee list and refund tickets.
- **MCP Apps** render a ticket card in the host.

Nothing here is meant to run. The packages are not installed, and the vulnerable server must never be deployed. All secrets in `vulnerable-v1` are fake.

## Try it

```bash
npm run build                       # once, from the repo root

node dist/cli.js scan showcase/mcp-dev-summit-toronto/vulnerable-v1
node dist/cli.js scan showcase/mcp-dev-summit-toronto/clean-v2

# CI gate: exits 1 on the vulnerable server, 0 on the clean one
node dist/cli.js scan showcase/mcp-dev-summit-toronto/vulnerable-v1 --ci --fail-on high

# Only the migration checks
node dist/cli.js scan showcase/mcp-dev-summit-toronto/vulnerable-v1 --rules migration,session-state

# SARIF for GitHub Code Scanning
node dist/cli.js scan showcase/mcp-dev-summit-toronto/vulnerable-v1 --format sarif --output summit.sarif
```

`npx vitest run tests/showcase.test.ts` asserts that the vulnerable server trips every rule and the clean one trips none.

> The showcase lives outside any `examples/`, `demos/` or `fixtures/` folder on purpose. MCPeek tags findings in those paths as example or test code and leaves them out of the score and the CI gate.

## What is wrong in `vulnerable-v1`, and where

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

This is the realistic middle state: checkout was moved to v2 first, and the new primitives were misused.

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

## How `clean-v2` fixes each one

- **Same tools, bounded inputs.** Every field has a type, length and format bound. Enums replace free text wherever the set is closed.
- **No shell, no eval.** `filter_schedule` takes two enums as bind parameters. `export_attendees` runs a fixed binary with `execFile`, with a format from a lookup table and a server-generated file name.
- **SQL uses bind parameters only**, including the helper in `db.ts`.
- **Slides** use `path.basename`, then `path.resolve` plus a prefix check against the slides folder.
- **Headshots** require https and a host on `ALLOWED_HEADSHOT_HOSTS`, with redirects disabled.
- **Stateless.** No session maps and no session id generator. Carts and confirmations ride in `requestState`.
- **Push becomes pull.** `buy_ticket` returns `inputRequired` with an elicitation, then charges on the retried call.
- **`requestState` is bound and keyed from the environment** (`src/state.ts`), and holds only a step and an id.
- **Authority comes from `ctx.http.authInfo`.** `_meta` and headers are never trusted, and ownership is re-checked before every mutation.
- **Receipts carry an opaque id** in the JWT, never payment data.
- **The ticket card escapes its HTML** and lists exact CSP origins.
- **Secrets come from the environment.** `.env` is git-ignored and `.env.example` holds placeholders.
- **Dependencies:** only `@modelcontextprotocol/server`, with a caret range below the next major.

## Keeping the showcase honest

`tests/showcase.test.ts` carries the list of every MCPeek rule. When a new rule ships, add it to that list and add the matching flaw to `vulnerable-v1`. The test fails until you do.
