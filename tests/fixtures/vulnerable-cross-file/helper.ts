import { execSync } from "child_process";
import { readFileSync } from "fs";

export function runShell(cmd: string): Buffer {
  return execSync(cmd);
}

export function readUserFile(p: string): string {
  return readFileSync(p, "utf8");
}
