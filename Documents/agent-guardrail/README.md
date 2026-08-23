# agent-guardrail

Minimal MCP server exposing a `run_command` tool with destructive-command guardrails.

## Stack

| | |
|---|---|
| Transport | `stdio` (MCP spec) |
| SDK | `@modelcontextprotocol/sdk` |
| Runtime | Node.js ≥ 18 + TypeScript |

---

## Tool: `run_command`

```jsonc
{
  "name": "run_command",
  "arguments": {
    "command": "ls -la",   // required – shell command to run
    "confirm": false        // optional – set true to execute blocked commands
  }
}
```

### Guardrail flow

```
run_command(command)
      │
      ▼
  blocklist check
      │
  ┌───┴─────────────┐
MATCH               NO MATCH
  │                    │
confirm?          execute ──► return stdout/stderr
  │
  ├─ false ──► return ⚠️ warning (not executed)
  │
  └─ true  ──► log to guardrail.log ──► execute
```

Blocked commands are **never executed** without `confirm: true`.

---

## Blocklist categories

| Category | Examples |
|---|---|
| File-system nukes | `rm -rf`, `shred`, `wipe`, `truncate` |
| Disk / partition | `mkfs`, `format C:`, `fdisk`, `dd of=/dev/…` |
| Shutdown / reboot | `shutdown`, `reboot`, `halt`, `poweroff` |
| Database drops | `DROP TABLE`, `TRUNCATE TABLE`, `DELETE FROM` |
| Cloud infra | `terraform destroy`, `kubectl delete`, `aws … delete` |
| Package removal | `npm uninstall -g`, `pip uninstall -y` |
| Fork bombs / chaos | `:(){:|:&}`, `killall`, `kill -9 1` |
| Credential exposure | `curl | sh`, `wget | sh`, `chmod 777`, `cat /etc/shadow` |

---

## guardrail.log format

One JSON object per line:

```jsonc
{
  "timestamp": "2026-08-23T16:00:00.000Z",
  "event": "BLOCKED",                   // or "CONFIRMED_DESTRUCTIVE"
  "command": "rm -rf /",
  "matchedPattern": "rm\\s+(-[a-z]*f…)"
}
```

> **Note:** Only blocked commands are logged. Safe commands that execute normally produce no log entry.

---

## Setup

```bash
npm install
npm run build       # tsc → dist/
npm start           # run the compiled server

# or for development
npm run dev         # ts-node index.ts
```

### Register with an MCP host (e.g., Claude Desktop)

Add to your `claude_desktop_config.json`:

```jsonc
{
  "mcpServers": {
    "agent-guardrail": {
      "command": "node",
      "args": ["C:/Users/USER/Documents/agent-guardrail/dist/index.js"]
    }
  }
}
```

---

## Extending the blocklist

Open `index.ts` and append entries to the `BLOCKLIST` array:

```typescript
{ pattern: /your-regex/i, reason: "Human-readable explanation" },
```
