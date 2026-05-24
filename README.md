# MCPeek

[![npm version](https://img.shields.io/npm/v/mcpeek.svg)](https://www.npmjs.com/package/mcpeek)
[![npm downloads](https://img.shields.io/npm/dm/mcpeek.svg)](https://www.npmjs.com/package/mcpeek)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Source-code security scanner for MCP (Model Context Protocol) server implementations.

Unlike config/runtime scanners, `mcpeek` reads your source code and detects vulnerabilities at the AST level — understanding MCP SDK patterns like `server.tool()` and `server.setRequestHandler()` and tracking taint from handler parameters to dangerous sinks.

## Quick start

```bash
# Scan a GitHub repo
npx mcpeek scan https://github.com/org/your-mcp-server

# Scan a local directory
npx mcpeek scan ./my-mcp-server

# Run only specific rules
npx mcpeek scan ./my-server --rules command-injection,sql-injection

# CI mode (exit 1 on high+ severity findings)
npx mcpeek scan ./my-server --ci --fail-on high

# Output as SARIF (GitHub Code Scanning compatible)
npx mcpeek scan ./my-server --format sarif --output findings.sarif
```

## Detection rules

| Rule | Severity | CWE | Description |
|------|----------|-----|-------------|
| `mcp-command-injection` | Critical | CWE-78 | Tool handler param flows to `exec` / `spawn` / `execFile` without sanitization |
| `mcp-code-injection` | Critical | CWE-94 | Tool handler param flows to `eval`, `new Function`, or `vm.runIn*` / `vm.Script` |
| `mcp-sql-injection` | Critical | CWE-89 | Tool handler param flows to raw DB query sinks (`query`, `$queryRawUnsafe`, `execute`, …) |
| `mcp-path-traversal` | High | CWE-22 | Tool handler param flows to `fs` operations without a boundary check |
| `mcp-ssrf` | High | CWE-918 | Tool handler param flows to `fetch` / `axios` / `got` without an allowlist |
| `mcp-tool-poisoning` | High | CWE-74 | Tool name/description contains prompt-injection keywords, hidden Unicode, ANSI escapes, or violates MCP naming rules |
| `mcp-missing-input-validation` | High | CWE-20 | Tool registered without a Zod schema |
| `mcp-hardcoded-credential` | High | CWE-798 | API key / token / secret hardcoded in source |
| `mcp-weak-input-validation` | Medium | CWE-20 | Schema uses `z.any()` / `z.unknown()` |
| `mcp-weak-schema-bounds` | Medium | CWE-20 | Zod schema accepts user input without size, range, or pattern bounds |

Each finding includes a `taintChain` showing how user input reaches the sink — e.g. `cmd (handler param) → command (line 3) → execSync() (line 5)`.

## Batch audit

```bash
# Scan all servers in a targets file
npx mcpeek audit --targets targets/top-30.json --output results/
```

The bundled `targets/top-30.json` lists verified TypeScript MCP servers and is what we use for the project's own corpus runs.

## Output formats

`--format markdown` (default), `json`, or `sarif`. SARIF 2.1.0 output includes `codeFlows` derived from the taint chain, so findings render in GitHub Code Scanning with the full path from parameter to sink.

## Install

```bash
npm install -g mcpeek
# or one-shot
npx mcpeek scan <target>
```

## Use in CI

Add MCPeek to any GitHub repo with the [MCPeek Action](https://github.com/iamakash-06/mcpeek-action):

```yaml
- uses: iamakash-06/mcpeek-action@v1
  with:
    target: .
    fail-on: high
```

To upload findings to GitHub Code Scanning (the job needs `security-events: write` so `upload-sarif` can post results):

```yaml
permissions:
  contents: read
  actions: read
  security-events: write

steps:
  - uses: iamakash-06/mcpeek-action@v1
    id: mcpeek
    with:
      format: sarif
      output: mcpeek.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: ${{ steps.mcpeek.outputs.report }}
```

## License

MIT
