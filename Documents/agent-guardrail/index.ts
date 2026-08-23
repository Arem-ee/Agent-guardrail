import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";


const execAsync = promisify(exec);

// ---------------------------------------------------------------------------
// Guardrail log
// ---------------------------------------------------------------------------
const LOG_FILE = path.join(process.cwd(), "guardrail.log");

function appendLog(entry: {
  timestamp: string;
  event: "BLOCKED" | "CONFIRMED_DESTRUCTIVE";
  command: string;
  matchedPattern: string;
}): void {
  const line = JSON.stringify(entry) + "\n";
  fs.appendFileSync(LOG_FILE, line, "utf8");
}

// ---------------------------------------------------------------------------
// Destructive-command blocklist
// Each entry has a human-readable reason alongside the pattern.
// ---------------------------------------------------------------------------
export interface BlocklistEntry {
  pattern: RegExp;
  reason: string;
}

export const BLOCKLIST: BlocklistEntry[] = [
  // File-system nukes
  { pattern: /rm\s+(-[a-z]*f[a-z]*|-[a-z]*r[a-z]*f[a-z]*|--force|--recursive)/i, reason: "Recursive or forced file removal (rm -rf / rm -f)" },
  { pattern: /\brm\b.*\/\s*$/i,                reason: "Removal targeting the filesystem root" },
  { pattern: /\brmdir\b/i,                     reason: "Directory removal" },
  { pattern: /\bshred\b/i,                     reason: "Secure file deletion (shred)" },
  { pattern: /\bwipe\b/i,                      reason: "Secure wipe utility" },
  { pattern: /\btruncate\b/i,                  reason: "File truncation to zero bytes" },

  // Disk / partition destruction
  { pattern: /\bmkfs\b/i,                      reason: "Filesystem formatting (mkfs)" },
  { pattern: /\bformat\b\s+[a-z]:/i,           reason: "Windows disk format" },
  { pattern: /\bfdisk\b/i,                     reason: "Partition table editor (fdisk)" },
  { pattern: /\bparted\b/i,                    reason: "Partition editor (parted)" },
  { pattern: /dd\s+.*of=\/dev\//i,             reason: "Raw disk write via dd" },
  { pattern: />\s*\/dev\/(sd[a-z]|hd[a-z]|nvme)/i, reason: "Redirect to raw block device" },

  // System shutdown / reboot
  { pattern: /\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b/i, reason: "System shutdown or reboot" },

  // Database drops
  { pattern: /drop\s+(database|table|schema)\b/i, reason: "SQL DROP DATABASE / TABLE / SCHEMA" },
  { pattern: /truncate\s+table\b/i,            reason: "SQL TRUNCATE TABLE" },
  { pattern: /delete\s+from\b/i,               reason: "SQL DELETE FROM (no WHERE guard)" },

  // Cloud / infra destruction
  { pattern: /terraform\s+destroy/i,           reason: "Terraform destroy" },
  { pattern: /kubectl\s+delete\b/i,            reason: "Kubernetes resource deletion" },
  { pattern: /aws\s+.*delete/i,                reason: "AWS CLI delete operation" },
  { pattern: /gcloud\s+.*delete/i,             reason: "GCP CLI delete operation" },
  { pattern: /az\s+.*delete/i,                 reason: "Azure CLI delete operation" },

  // Package / dependency mass-removal
  { pattern: /npm\s+(uninstall|remove)\s+-g/i, reason: "Global npm package removal" },
  { pattern: /pip\s+uninstall\s+-y/i,          reason: "Batch pip uninstall" },

  // Fork bombs & chaos
  { pattern: /:\(\)\s*\{.*:\|:&\s*\}/,         reason: "Fork bomb detected" },
  { pattern: /\bkillall\b/i,                   reason: "Kill all processes (killall)" },
  { pattern: /kill\s+-9\s+1\b/,               reason: "Killing PID 1 (init)" },

  // Credential exposure / exfiltration
  { pattern: /curl.*\|\s*(ba)?sh/i,            reason: "Remote script execution via curl | sh" },
  { pattern: /wget.*\|\s*(ba)?sh/i,            reason: "Remote script execution via wget | sh" },
  { pattern: /\bchmod\s+777\b/i,               reason: "World-writable permissions (chmod 777)" },
  { pattern: /\bchown\s+-R\b/i,               reason: "Recursive ownership change" },
  { pattern: /> \/etc\/(passwd|shadow|sudoers)/i, reason: "Overwriting system credentials file" },
  { pattern: /cat\s+\/etc\/shadow/i,           reason: "Reading shadow password file" },
];

// ---------------------------------------------------------------------------
// Check command against blocklist — returns first match or null
// ---------------------------------------------------------------------------
function checkBlocklist(command: string): BlocklistEntry | null {
  for (const entry of BLOCKLIST) {
    if (entry.pattern.test(command)) {
      return entry;
    }
  }
  return null;
}

/**
 * Public helper — returns the first matching BlocklistEntry if the command
 * is destructive, or null if it's safe. Import this in demo.ts or tests.
 */
export function isBlocked(command: string): BlocklistEntry | null {
  return checkBlocklist(command);
}

// ---------------------------------------------------------------------------
// MCP server setup
// ---------------------------------------------------------------------------
const server = new McpServer({
  name: "agent-guardrail",
  version: "1.0.0",
});

server.tool(
  "run_command",
  "Execute a shell command. Destructive commands require explicit confirmation.",
  {
    command: z.string().describe("The shell command to execute"),
    confirm: z
      .boolean()
      .optional()
      .describe(
        "Set to true to confirm execution of a flagged destructive command"
      ),
  },
  async ({ command, confirm }) => {
    const timestamp = new Date().toISOString();
    const match = checkBlocklist(command);

    // -----------------------------------------------------------------------
    // Blocked path
    // -----------------------------------------------------------------------
    if (match) {
      if (!confirm) {
        // Warn but do NOT execute
        return {
          content: [
            {
              type: "text",
              text: [
                `⚠️  **Destructive command detected — not executed.**`,
                ``,
                `**Command:** \`${command}\``,
                `**Risk:** ${match.reason}`,
                `**Pattern matched:** \`${match.pattern.source}\``,
                ``,
                `To proceed anyway, re-submit the same call with **\`confirm: true\`**.`,
                `Only do so if you fully understand the consequences and have a backup plan.`,
              ].join("\n"),
            },
          ],
        };
      }

      // confirm === true: log and proceed
      appendLog({
        timestamp,
        event: "CONFIRMED_DESTRUCTIVE",
        command,
        matchedPattern: match.pattern.source,
      });
    }

    // -----------------------------------------------------------------------
    // Safe (or confirmed) — execute
    // -----------------------------------------------------------------------
    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout: 30_000,   // 30 s hard cap
        maxBuffer: 5 * 1024 * 1024, // 5 MB
        shell: process.platform === "win32" ? "cmd.exe" : "/bin/bash",
      });

      return {
        content: [
          {
            type: "text",
            text: [
              stdout ? `**stdout:**\n\`\`\`\n${stdout.trimEnd()}\n\`\`\`` : "",
              stderr ? `**stderr:**\n\`\`\`\n${stderr.trimEnd()}\n\`\`\`` : "",
              !stdout && !stderr ? "*(command produced no output)*" : "",
            ]
              .filter(Boolean)
              .join("\n\n"),
          },
        ],
      };
    } catch (err: unknown) {
      const e = err as { stdout?: string; stderr?: string; message?: string };
      return {
        content: [
          {
            type: "text",
            text: [
              `**Command failed.**`,
              e.stdout ? `**stdout:**\n\`\`\`\n${e.stdout.trimEnd()}\n\`\`\`` : "",
              e.stderr ? `**stderr:**\n\`\`\`\n${e.stderr.trimEnd()}\n\`\`\`` : "",
              `**Error:** ${e.message ?? String(err)}`,
            ]
              .filter(Boolean)
              .join("\n\n"),
          },
        ],
        isError: true,
      };
    }
  }
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // MCP servers must not write to stdout (it's the protocol channel).
  // Diagnostics go to stderr.
  process.stderr.write("agent-guardrail MCP server running on stdio\n");
}

const isMain = process.argv[1] && (
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url)) ||
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url).replace(/\.ts$/, ".js"))
);

if (isMain) {
  main().catch((err) => {
    process.stderr.write(`Fatal: ${err}\n`);
    process.exit(1);
  });
}
