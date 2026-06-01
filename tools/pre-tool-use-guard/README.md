# PreToolUse Guard — Destructive Command Blocker

A Claude Code `PreToolUse` hook that intercepts and blocks dangerous bash commands before execution.

## What It Blocks

| Pattern | Example |
|---------|---------|
| `rm -rf` / `rm -fr` | `rm -rf /`, `rm -r -f .` |
| `git push --force` | `git push --force origin main` |
| `DROP TABLE` | `DROP TABLE users;` |
| `TRUNCATE` | `TRUNCATE TABLE orders;` |
| `DELETE FROM` without `WHERE` | `DELETE FROM users;` |

Safe commands pass through without interference.

## Install (2 commands)

```bash
git clone https://github.com/claude-builders-bounty/claude-builders-bounty.git
./claude-builders-bounty/tools/pre-tool-use-guard/install.sh
```

The installer copies the hook to `~/.claude/hooks/` and registers it in `~/.claude/settings.json`.

## How It Works

1. Claude Code invokes the hook before every `Bash` tool call
2. The hook reads the command from stdin JSON
3. If a destructive pattern matches, it returns a `deny` decision with an explanation
4. Every blocked attempt is logged to `~/.claude/hooks/blocked.log`

Log format (TSV):
```
2026-06-01T12:00:00Z    rm -rf /    /home/user/project    Destructive file removal (rm -rf)
```

## Uninstall

```bash
rm ~/.claude/hooks/block-destructive.sh
```

Then remove the corresponding entry from `~/.claude/settings.json` under `hooks.PreToolUse`.

## Limitations

The hook inspects the literal command string. It cannot catch:
- Base64-encoded or `eval`-wrapped commands
- Variable indirection (`CMD="rm"; $CMD -rf /`)
- Equivalent destructive operations via other tools (e.g., `find / -delete`)

SQL patterns (`DROP TABLE`, `TRUNCATE`, `DELETE FROM`) are matched anywhere in the command text, including in contexts like `grep "DROP TABLE" file.sql`. This is an intentional conservative trade-off.

## Requirements

- `bash` (3.2+)
- `jq`
