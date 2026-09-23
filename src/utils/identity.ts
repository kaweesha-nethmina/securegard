import * as vscode from "vscode";
import { spawn } from "child_process";
import { IdentitySource } from "../types";

export interface ResolvedIdentity {
  username: string;
  email?: string;
  source: IdentitySource;
}

const GLOBAL_USERNAME_KEY = "secuguard.githubUsername";

let cached: ResolvedIdentity | null = null;

function run(cmd: string, args: string[], cwd: string): Promise<string> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", () => resolve(""));
    child.on("close", (code) => resolve(code === 0 ? stdout.trim() : ""));
  });
}

function attr() {
  return vscode.workspace.getConfiguration("secuguard");
}

export function clearIdentityCache(): void {
  cached = null;
}

/**
 * Resolve "who is making this change" as a GitHub username, in priority order:
 *   1. secuguard.attribution.githubUsername setting
 *   2. `gh` CLI (gh api user --jq .login), cached per session
 *   3. `git config user.name` (+ user.email), flagged as unverified in the UI
 *   4. one-time prompt, persisted to context.globalState
 */
export async function resolveIdentity(context: vscode.ExtensionContext, workspaceRoot: string): Promise<ResolvedIdentity> {
  if (cached) return cached;

  const explicit = attr().get<string>("attribution.githubUsername", "");
  if (explicit.trim()) {
    cached = { username: explicit.trim(), source: "setting" };
    return cached;
  }

  if (attr().get<boolean>("attribution.autoDetect", true)) {
    const ghLogin = await run("gh", ["api", "user", "--jq", ".login"], workspaceRoot);
    if (ghLogin) {
      cached = { username: ghLogin, source: "gh" };
      return cached;
    }
    const gitName = await run("git", ["config", "user.name"], workspaceRoot);
    if (gitName) {
      const gitEmail = await run("git", ["config", "user.email"], workspaceRoot);
      cached = { username: gitName, ...(gitEmail ? { email: gitEmail } : {}), source: "git" };
      return cached;
    }
  }

  const stored = context.globalState.get<string>(GLOBAL_USERNAME_KEY);
  if (stored?.trim()) {
    cached = { username: stored.trim(), source: "prompt" };
    return cached;
  }

  const answer = await vscode.window.showInputBox({
    prompt: "What's your GitHub username? Used to attribute SecuGuard status changes.",
    placeHolder: "GitHub username",
    ignoreFocusOut: true,
  });
  const username = answer?.trim() || "unknown";
  await context.globalState.update(GLOBAL_USERNAME_KEY, username);
  cached = { username, source: "prompt" };
  return cached;
}