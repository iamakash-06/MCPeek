import { mkdtempSync, rmSync, existsSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { simpleGit } from "simple-git";

export interface FetchResult {
  path: string;
  cleanup: () => void;
  isTemp: boolean;
}

const GITHUB_URL_RE =
  /^https?:\/\/github\.com\/([^/]+\/[^/]+?)(?:\.git)?\/?$/;

export function isGitHubUrl(input: string): boolean {
  return GITHUB_URL_RE.test(input);
}

export async function fetchRepo(target: string): Promise<FetchResult> {
  if (!isGitHubUrl(target)) {
    // Local path — return as-is with a no-op cleanup
    if (!existsSync(target)) {
      throw new Error(`Path does not exist: ${target}`);
    }
    return { path: target, cleanup: () => {}, isTemp: false };
  }

  const tmpDir = mkdtempSync(join(tmpdir(), "mcp-audit-"));

  try {
    const git = simpleGit();
    await git.clone(target, tmpDir, ["--depth", "1", "--single-branch"]);
  } catch (err) {
    rmSync(tmpDir, { recursive: true, force: true });
    throw new Error(`Failed to clone ${target}: ${(err as Error).message}`);
  }

  return {
    path: tmpDir,
    cleanup: () => rmSync(tmpDir, { recursive: true, force: true }),
    isTemp: true,
  };
}
