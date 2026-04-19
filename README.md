# mcp-audit

Source-code-level security scanner for MCP server implementations.

Unlike config/runtime scanners, `mcp-audit` reads your source code and detects vulnerabilities at the AST level — understanding MCP SDK patterns like `server.tool()` handler flows.

## Quick start

```bash
# Scan a GitHub repo
npx mcp-audit scan https://github.com/org/your-mcp-server

# Scan a local directory
npx mcp-audit scan ./my-mcp-server

# CI mode (exit 1 on high+ severity findings)
npx mcp-audit scan ./my-server --ci --fail-on high

# Output as SARIF (GitHub Code Scanning compatible)
npx mcp-audit scan ./my-server --format sarif --output findings.sarif
```

## Detection rules

| Rule | Severity | CWE | Description |
|------|----------|-----|-------------|
| `mcp-command-injection` | Critical | CWE-78 | Tool handler param flows to exec/spawn without sanitization |
| `mcp-missing-input-validation` | High | CWE-20 | Tool registered without a Zod schema |
| `mcp-weak-input-validation` | Medium | CWE-20 | Schema uses `z.any()` / `z.unknown()` |
| `mcp-hardcoded-credential` | High | CWE-798 | API key/token/secret hardcoded in source |
| `mcp-path-traversal` | High | CWE-22 | User path flows to fs operations without boundary check |
| `mcp-ssrf` | High | CWE-918 | User URL flows to fetch/axios without allowlist |

## Batch audit

```bash
# Scan all servers in a targets file
npx mcp-audit audit --targets targets/top-30.json --output results/
```

## Install

```bash
npm install -g mcp-audit
# or
npx mcp-audit scan <target>
```

## License

MIT
