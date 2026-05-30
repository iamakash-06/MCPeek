import { SourceFile, SyntaxKind, Node } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames } from "../taint-tracker.js";
import { findTaintedReaching } from "../taint-match.js";
import { findMCPToolHandlers, type HandlerScanOptions } from "../mcp-handler.js";
import { extractSnippet } from "../snippet.js";

const PATH_HELPERS = new Set(["path.resolve", "path.normalize", "resolve", "normalize"]);

function isContainedPathCall(pathArg: Node, handlerBody: Node): boolean {
  let target: Node = pathArg;

  const ident = pathArg.asKind(SyntaxKind.Identifier);
  if (ident) {
    try {
      for (const def of ident.getDefinitionNodes()) {
        const init = def.asKind(SyntaxKind.VariableDeclaration)?.getInitializer();
        if (init) {
          target = init;
          break;
        }
      }
    } catch {
      // fall through to the original node
    }
  }

  const call = target.asKind(SyntaxKind.CallExpression);
  if (!call) return false;
  const callee = call.getExpression().getText();
  if (!PATH_HELPERS.has(callee)) return false;
  if (call.getArguments().length < 2) return false;

  const body = handlerBody.getText();
  return /\.startsWith\s*\(/.test(body) || /path\.relative\s*\(/.test(body);
}

const FS_SINKS = new Set([
  "readFile",
  "readFileSync",
  "writeFile",
  "writeFileSync",
  "appendFile",
  "appendFileSync",
  "createReadStream",
  "createWriteStream",
  "open",
  "openSync",
  "unlink",
  "unlinkSync",
  "rmdir",
  "rmdirSync",
  "mkdir",
  "mkdirSync",
  "stat",
  "statSync",
  "lstat",
  "lstatSync",
  "access",
  "accessSync",
  "rename",
  "renameSync",
]);

export function detectPathTraversal(
  sourceFile: SourceFile,
  options: HandlerScanOptions = {}
): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile, options)) {
    if (!handlerBody || paramNames.length === 0) continue;

    const tainted = getTaintedNames(handlerBody, paramNames);
    const calls = handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression);

    for (const call of calls) {
      const callText = call.getExpression().getText();
      const funcName = callText.split(".").pop() ?? callText;

      if (!FS_SINKS.has(funcName)) continue;

      const args = call.getArguments();
      if (args.length === 0) continue;

      const pathArg = args[0];
      const matched = findTaintedReaching(pathArg, tainted);

      if (!matched) continue;

      // Treat a path.resolve/normalize wrapper as safe only when it joins the
      // user input against a base dir AND a containment check (.startsWith
      // / path.relative) appears in the handler. A bare path.resolve(userInput)
      // still resolves /etc/passwd.
      const hasSafeWrapper = isContainedPathCall(pathArg, handlerBody);

      if (!hasSafeWrapper) {
        const lineNum = call.getStartLineNumber();
        const { column } = sourceFile.getLineAndColumnAtPos(call.getStart());

        findings.push({
          rule: "mcp-path-traversal",
          severity: "high",
          cwe: "CWE-22",
          file: filePath,
          line: lineNum,
          column,
          message: `User-controlled path flows to ${funcName}() without proper boundary validation`,
          evidence: extractSnippet(sourceFile, lineNum, 3),
          remediation:
            "Use path.resolve(BASE_DIR, userInput) and verify the result starts with BASE_DIR before accessing the filesystem.",
          confidence: "high",
          taintChain: [...matched.chain, `${funcName}() (line ${lineNum})`],
        });
      }
    }
  }

  return findings;
}
