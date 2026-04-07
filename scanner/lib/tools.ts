// scanner/lib/tools.ts

export async function runTool(
  name: string,
  args: string[],
  timeoutMs: number = 60000
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const proc = Bun.spawn(args, {
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env },
    });

    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => {
        proc.kill();
        reject(new Error(`${name} timed out after ${timeoutMs / 1000}s`));
      }, timeoutMs)
    );

    const result = Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);

    const [stdout, stderr, exitCode] = (await Promise.race([
      result,
      timeout,
    ])) as [string, string, number];
    return { stdout, stderr, exitCode };
  } catch (error: any) {
    return { stdout: "", stderr: error.message, exitCode: 1 };
  }
}

export async function checkTool(name: string): Promise<boolean> {
  const r = await runTool(name, ["which", name], 5000);
  return r.exitCode === 0;
}

export function parseGithubUrl(input: string): { owner: string; name: string } {
  const cleaned = input.replace(/\.git$/, "").replace(/\/$/, "");
  const match = cleaned.match(/(?:github\.com\/)?([^\/]+)\/([^\/]+)$/);
  if (!match) throw new Error(`Cannot parse GitHub URL: ${input}`);
  return { owner: match[1], name: match[2] };
}

export function safeParseJson(text: string): any {
  try { return JSON.parse(text); } catch { return null; }
}

export function monthsAgo(dateStr: string): number {
  return (Date.now() - new Date(dateStr).getTime()) / (1000 * 60 * 60 * 24 * 30);
}
