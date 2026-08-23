/**
 * demo.ts — terminal demo for agent-guardrail
 *
 * Run with:  npm run demo
 *
 * Shows two scenarios:
 *   1. Blocked command (no confirm) → ⚠️  warning, nothing executed
 *   2. Same command with confirm:true → ✅ logged + executed (dry-run safe)
 */

import { isBlocked } from "./index.js";
import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as path from "path";

const execAsync = promisify(exec);
const LOG_FILE = path.join(process.cwd(), "guardrail.log");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function printCommand(command: string) {
  console.log();
  console.log(`  \x1b[90m$\x1b[0m \x1b[1m${command}\x1b[0m`);
}

function printBlocked(reason: string) {
  console.log(
    `  \x1b[33m⚠️  BLOCKED\x1b[0m  — ${reason}`
  );
  console.log(
    `  \x1b[90mAdd confirm: true to run anyway. Nothing was executed.\x1b[0m`
  );
}

function printConfirmed(command: string, matchedPattern: string) {
  const entry = {
    timestamp: new Date().toISOString(),
    event: "CONFIRMED_DESTRUCTIVE" as const,
    command,
    matchedPattern,
  };
  fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + "\n", "utf8");
  console.log(`  \x1b[32m✅ CONFIRMED — logged to guardrail.log\x1b[0m`);
}

async function runCommand(command: string): Promise<void> {
  try {
    const { stdout, stderr } = await execAsync(command, {
      timeout: 10_000,
      shell: process.platform === "win32" ? "cmd.exe" : "/bin/bash",
    });
    if (stdout) console.log(`  \x1b[90m${stdout.trimEnd()}\x1b[0m`);
    if (stderr) console.log(`  \x1b[90mstderr: ${stderr.trimEnd()}\x1b[0m`);
    if (!stdout && !stderr) console.log(`  \x1b[90m(no output)\x1b[0m`);
  } catch (err: unknown) {
    const e = err as { message?: string };
    console.log(`  \x1b[31mError: ${e.message ?? String(err)}\x1b[0m`);
  }
}

// ---------------------------------------------------------------------------
// Demo scenarios
// ---------------------------------------------------------------------------
async function demo() {
  const COMMAND = "rm -rf ./important-folder";

  console.log("\x1b[1m\x1b[36m  agent-guardrail demo\x1b[0m");
  console.log("  \x1b[90m─────────────────────────────────────────\x1b[0m");

  // ------------------------------------------------------------------
  // Scenario 1: no confirm — should be blocked
  // ------------------------------------------------------------------
  console.log("\n  \x1b[90mScenario 1 — destructive command, no confirmation\x1b[0m");
  printCommand(COMMAND);

  const match = isBlocked(COMMAND);
  if (match) {
    printBlocked(match.reason);
  } else {
    await runCommand(COMMAND);
  }

  // ------------------------------------------------------------------
  // Scenario 2: confirm: true — log + execute
  // ------------------------------------------------------------------
  console.log("\n  \x1b[90mScenario 2 — same command, confirm: true\x1b[0m");
  printCommand(`${COMMAND}  { confirm: true }`);

  const match2 = isBlocked(COMMAND);
  if (match2) {
    printConfirmed(COMMAND, match2.pattern.source);
    // Use a cross-platform echo to show that execution proceeds after confirmation.
    const safeEcho =
      process.platform === "win32"
        ? `echo Executing: ${COMMAND}`
        : `echo "Executing: ${COMMAND}"`;
    await runCommand(safeEcho);
  } else {
    await runCommand(COMMAND);
  }

  console.log();
  console.log("  \x1b[90m─────────────────────────────────────────\x1b[0m");
  console.log("  \x1b[90mguardrail.log entry written for scenario 2.\x1b[0m");
  console.log();
}

demo().catch((err) => {
  console.error(err);
  process.exit(1);
});
