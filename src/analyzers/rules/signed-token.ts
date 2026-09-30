import { Node, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";
import { secretPayloadFields } from "./request-state.js";

const JWT_SIGN_RE = /(^|\.)(jwt|jsonwebtoken|jws)\.sign$|^sign$|^signJwt$/i;

export function detectSignedTokenSecrets(sourceFile: SourceFile): Finding[] {
  const text = sourceFile.getFullText();
  if (!/jsonwebtoken|jose|\bjwt\b|SignJWT/i.test(text)) return [];
  const findings: Finding[] = [];

  for (const node of [...sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression), ...sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)]) {
    const callee = node.getExpression().getText();
    const isSigner = Node.isNewExpression(node) ? callee === "SignJWT" : JWT_SIGN_RE.test(callee);
    const payload = node.getArguments()[0];
    if (!isSigner || !payload) continue;
    const fields = secretPayloadFields(payload, false);
    if (fields.length === 0) continue;

    const line = node.getStartLineNumber();
    findings.push({
      rule: "mcp-signed-token-secret",
      severity: "high",
      cwe: "CWE-312",
      file: sourceFile.getFilePath(),
      line,
      column: sourceFile.getLineAndColumnAtPos(node.getStart()).column,
      message: `Secret-looking data is placed in a signed token, which is readable by anyone who holds it: ${fields.join(", ")}`,
      evidence: extractSnippet(sourceFile, line, 3),
      remediation: "Encrypt the token (for example AES-GCM or JWE), or keep the secret server-side and sign only an opaque reference.",
      confidence: "medium",
    });
  }
  return findings;
}
