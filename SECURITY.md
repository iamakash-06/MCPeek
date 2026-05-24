# Security Policy

MCPeek is a security scanner for MCP servers, so we take the security of the tool itself seriously. If you find a vulnerability in MCPeek (the scanner) — not in a third-party MCP server it scans — please report it privately.

## Reporting a vulnerability

Use GitHub's **[private vulnerability reporting](https://github.com/iamakash-06/MCPeek/security/advisories/new)** to open a confidential advisory. This is the preferred channel.

If you cannot use GitHub advisories, email **sathishakash2003@gmail.com** with the subject line `MCPeek security report` and as much detail as you can share:

- Affected version (output of `npx mcpeek --version`)
- Reproduction steps or a minimal proof of concept
- Impact assessment (what an attacker can achieve)
- Any suggested remediation

Please **do not** open public issues, pull requests, or discussions for suspected vulnerabilities until a fix has shipped.

## Response timeline

| Stage | Target |
|---|---|
| Acknowledgement of report | within 3 business days |
| Initial assessment (in scope / out of scope, severity) | within 7 business days |
| Fix or mitigation released | depends on severity; critical issues prioritized |
| Public advisory and CVE (if applicable) | after a fix is available |

## Scope

**In scope**

- Code execution, sandbox escape, or unauthorized filesystem/network access triggered by running `mcpeek scan` against an untrusted repository
- Vulnerabilities in MCPeek's parsing, dependency handling, or report generation
- Supply-chain issues affecting the published `mcpeek` npm package

**Out of scope**

- Vulnerabilities in MCP servers that MCPeek scans (please report those to the server's authors)
- Findings from running MCPeek against your own repository (these are scanner output, not vulnerabilities in MCPeek)
- Issues that require an already-compromised local machine

## Supported versions

Only the latest released minor version on npm receives security fixes. Older versions are not patched.

## Safe harbor

Good-faith security research is welcome. We will not pursue legal action against researchers who report vulnerabilities through the channels above and avoid privacy violations, service disruption, or data destruction.
