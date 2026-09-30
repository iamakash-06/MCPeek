import { Node, SourceFile, SyntaxKind, CallExpression } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";
import { resolveSchemaDefinition } from "../cross-file.js";

export const SECRET_NAME_RE =
  /pass(word|wd)?|secret|api[_-]?key|apikey|private[_-]?key|credential|bearer|cookie|authorization|(?<!next|page|progress|continuation|cursor|max|total|input|output)_?token(?!s?(Count|Limit|Budget))/i;

const RANDOM_KEY_RE = /random(Bytes|UUID|Fill)|getRandomValues|nanoid|uuid/i;

function finding(
  sf: SourceFile,
  node: Node,
  rule: string,
  severity: Finding["severity"],
  cwe: string,
  confidence: Finding["confidence"],
  message: string,
  remediation: string
): Finding {
  const line = node.getStartLineNumber();
  return {
    rule,
    severity,
    cwe,
    file: sf.getFilePath(),
    line,
    column: sf.getLineAndColumnAtPos(node.getStart()).column,
    message,
    evidence: extractSnippet(sf, line, 3),
    remediation,
    confidence,
  };
}

function objectArg(call: CallExpression, index: number) {
  const arg = call.getArguments()[index];
  return arg ? resolveSchemaDefinition(arg).asKind(SyntaxKind.ObjectLiteralExpression) : undefined;
}

function keyKind(node: Node): "literal" | "random" | undefined {
  const resolved = resolveSchemaDefinition(node);
  if (Node.isStringLiteral(resolved) || Node.isNoSubstitutionTemplateLiteral(resolved)) return "literal";
  if (Node.isBinaryExpression(resolved)) {
    const op = resolved.getOperatorToken().getText();
    if (op === "??" || op === "||") return keyKind(resolved.getRight());
  }
  if (Node.isCallExpression(resolved) && RANDOM_KEY_RE.test(resolved.getExpression().getText())) return "random";
  return undefined;
}

function isCodecReceiver(receiver: Node): boolean {
  const text = receiver.getText();
  if (/codec|state/i.test(text)) return true;
  const init = resolveSchemaDefinition(receiver);
  return init !== receiver && init.getText().startsWith("createRequestStateCodec");
}

export function secretPayloadFields(payload: Node, includeEnvReads = true): string[] {
  const obj = resolveSchemaDefinition(payload).asKind(SyntaxKind.ObjectLiteralExpression);
  if (!obj) return [];
  const hits: string[] = [];
  for (const prop of obj.getProperties()) {
    const name = Node.isPropertyAssignment(prop) || Node.isShorthandPropertyAssignment(prop) ? prop.getName() : "";
    const value = Node.isPropertyAssignment(prop) ? prop.getInitializer() : prop;
    const idents = value?.getDescendantsOfKind(SyntaxKind.Identifier).map((i) => i.getText()) ?? [];
    const envRead = includeEnvReads && /process\.env|import\.meta\.env/.test(value?.getText() ?? "");
    if (SECRET_NAME_RE.test(name) || idents.some((i) => SECRET_NAME_RE.test(i)) || envRead) hits.push(name);
  }
  return hits;
}

export function detectRequestState(sourceFile: SourceFile): Finding[] {
  if (!sourceFile.getFullText().includes("createRequestStateCodec") && !sourceFile.getFullText().includes(".mint(")) {
    return [];
  }
  const findings: Finding[] = [];

  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression();
    const calleeText = callee.getText();

    if (calleeText === "createRequestStateCodec" || calleeText.endsWith(".createRequestStateCodec")) {
      const options = objectArg(call, 0);
      if (!options || options.getProperties().some((p) => Node.isSpreadAssignment(p))) continue;

      if (!options.getProperty("bind")) {
        findings.push(
          finding(
            sourceFile, call, "mcp-requeststate-unbound", "high", "CWE-345", "medium",
            "requestState codec has no bind callback, so a minted state can be replayed by a different principal or method",
            "Pass bind: ctx => `${ctx.mcpReq.method}\\0${ctx.http?.authInfo?.clientId ?? ''}` and hand ctx to mint()."
          )
        );
      }

      const key = options.getProperty("key");
      const keyValue = key && (Node.isPropertyAssignment(key) ? key.getInitializer() : Node.isShorthandPropertyAssignment(key) ? key.getNameNode() : undefined);
      const kind = keyValue && keyKind(keyValue);
      if (kind === "literal") {
        findings.push(
          finding(
            sourceFile, keyValue!, "mcp-requeststate-weak-key", "high", "CWE-321", "high",
            "requestState codec key is hardcoded in source, so anyone with the code can forge state",
            "Load the key from a secret store or environment variable with no literal fallback."
          )
        );
      } else if (kind === "random") {
        findings.push(
          finding(
            sourceFile, keyValue!, "mcp-requeststate-weak-key", "medium", "CWE-320", "medium",
            "requestState codec key is generated per process, so state fails across instances and restarts",
            "Use one shared key from a secret store so every instance can verify echoed state."
          )
        );
      }
      continue;
    }

    const pa = callee.asKind(SyntaxKind.PropertyAccessExpression);
    if (pa?.getName() === "mint" && call.getArguments().length > 0 && isCodecReceiver(pa.getExpression())) {
      const fields = secretPayloadFields(call.getArguments()[0]);
      if (fields.length > 0) {
        findings.push(
          finding(
            sourceFile, call, "mcp-requeststate-secret", "high", "CWE-312", "medium",
            `Secret-looking data is minted into requestState, which is signed but not encrypted: ${fields.join(", ")}`,
            "Keep secrets server-side and store only an opaque reference in requestState."
          )
        );
      }
    }
  }
  return findings;
}
