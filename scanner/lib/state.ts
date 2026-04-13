// scanner/lib/state.ts
import { join } from "path";
import { homedir } from "os";
import { mkdirSync } from "fs";
import { safeParseJson } from "./tools.ts";
import type { ScanState } from "../types.ts";

const STATE_DIR = join(homedir(), ".repo-scanner", "state"); // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
mkdirSync(STATE_DIR, { recursive: true });

export function stateFile(owner: string, name: string): string {
  return join(STATE_DIR, `${owner}-${name}.json`); // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
}

export async function loadStateAsync(owner: string, name: string): Promise<ScanState | null> {
  const path = stateFile(owner, name);
  const file = Bun.file(path);
  const exists = await file.exists();
  if (!exists) return null;
  try { return safeParseJson(await file.text()) as ScanState; } catch { return null; }
}

export async function saveState(state: ScanState): Promise<void> {
  const path = stateFile(state.owner, state.name);
  await Bun.write(path, JSON.stringify(state, null, 2));
}

export async function clearState(owner: string, name: string): Promise<void> {
  const { unlink } = await import("fs/promises");
  try { await unlink(stateFile(owner, name)); } catch {}
}
