import { mkdtempSync, rmSync, existsSync, mkdirSync } from "fs";
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

function buildCloneUrl(url: string): string {
  // Keep URLs token-free; auth is injected via git environment when available.
  return url;
}

function buildGitEnvForClone(url: string): NodeJS.ProcessEnv {
  const token = process.env.GITHUB_TOKEN;
  if (!token || !isGitHubUrl(url)) return {};

  const basicAuth = Buffer.from(`x-access-token:${token}`).toString("base64");
  return {
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader",
    GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${basicAuth}`,
    GIT_TERMINAL_PROMPT: "0",
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retries an async operation up to `attempts` times with exponential backoff
 * (1 s, 2 s, 4 s, …). Throws on the final failure.
 */
async function withRetry<T>(fn: () => Promise<T>, attempts = 3): Promise<T> {
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i === attempts - 1) throw err;
      await sleep(Math.pow(2, i) * 1000);
    }
  }
  // unreachable — satisfies TypeScript
  throw new Error("withRetry exhausted");
}

export async function fetchRepo(target: string): Promise<FetchResult> {
  if (!isGitHubUrl(target)) {
    // Local path — return as-is with a no-op cleanup
    if (!existsSync(target)) {
      throw new Error(`Path does not exist: ${target}`);
    }
    return { path: target, cleanup: () => {}, isTemp: false };
  }

  const tmpDir = mkdtempSync(join(tmpdir(), "mcpeek-"));

  try {
    const cloneUrl = buildCloneUrl(target);
    const git = simpleGit().env(buildGitEnvForClone(target));
    await withRetry(async () => {
      rmSync(tmpDir, { recursive: true, force: true });
      mkdirSync(tmpDir, { recursive: true });
      await git.clone(cloneUrl, tmpDir, ["--depth", "1", "--single-branch"]);
    });
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
