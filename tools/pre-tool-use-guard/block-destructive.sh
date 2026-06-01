#!/usr/bin/env bash
set -uo pipefail

LOG_FILE="${HOME}/.claude/hooks/blocked.log"

deny() {
  local reason="$1"
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$reason"
  exit 0
}

if ! command -v jq &>/dev/null; then
  deny "[HOOK ERROR] jq is not installed. Safety guard cannot parse commands. Install jq to restore protection."
fi

INPUT=$(cat)

if [[ -z "$INPUT" ]]; then
  deny "[HOOK ERROR] Received empty input; cannot verify command safety."
fi

COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null) || {
  deny "[HOOK ERROR] Failed to parse hook input JSON."
}

TOOL_NAME=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // "unknown"' 2>/dev/null)

if [[ "$TOOL_NAME" == "Bash" && -z "$COMMAND" ]]; then
  deny "[HOOK ERROR] Bash tool detected but .tool_input.command is missing."
fi

if [[ -z "$COMMAND" ]]; then
  exit 0
fi

CMD_LOWER=$(printf '%s' "$COMMAND" | tr '[:upper:]' '[:lower:]')

block() {
  local reason="$1"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  mkdir -p "$(dirname "$LOG_FILE")"
  printf '%s\t%s\t%s\t%s\n' "$timestamp" "$COMMAND" "$CWD" "$reason" >> "$LOG_FILE"

  deny "[BLOCKED] $reason. Use a safer alternative or ask the user for confirmation."
}

# --- rm -rf detection ---
# Matches: rm -rf, rm -fr, rm -r -f, rm --recursive --force, sudo rm -rf, find -exec rm -rf, xargs rm -rf
has_rm=false
if printf '%s' "$CMD_LOWER" | grep -qE '(^|[;&|]\s*|sudo\s+|xargs\s+|exec\s+|env\s+)rm\s'; then
  has_rm=true
fi
if printf '%s' "$CMD_LOWER" | grep -qE 'find\s.*rm\s'; then
  has_rm=true
fi

if [[ "$has_rm" == "true" ]]; then
  # -rf or -fr (combined)
  if printf '%s' "$CMD_LOWER" | grep -qE '\s-rf(\s|$)|\s-fr(\s|$)'; then
    block "Destructive file removal (rm -rf)"
  fi
  # Flags with r and f interleaved: -rif, -fir, etc.
  if printf '%s' "$CMD_LOWER" | grep -qE '\s-[a-z]*r[a-z]*f[a-z]*(\s|$)|\s-[a-z]*f[a-z]*r[a-z]*(\s|$)'; then
    block "Destructive file removal (rm -rf)"
  fi
  # Split flags: -r ... -f or -f ... -r
  if printf '%s' "$CMD_LOWER" | grep -qE '\s-r(\s|$)' && printf '%s' "$CMD_LOWER" | grep -qE '\s-f(\s|$)'; then
    block "Destructive file removal (rm -rf)"
  fi
  # Long-form: --recursive + --force
  if printf '%s' "$CMD_LOWER" | grep -qE '\s--recursive(\s|$)' && printf '%s' "$CMD_LOWER" | grep -qE '\s--force(\s|$)'; then
    block "Destructive file removal (rm --recursive --force)"
  fi
  # Mixed: -r --force OR --recursive -f
  if printf '%s' "$CMD_LOWER" | grep -qE '\s-r(\s|$)|\s--recursive(\s|$)'; then
    if printf '%s' "$CMD_LOWER" | grep -qE '\s--force(\s|$)|\s-f(\s|$)'; then
      block "Destructive file removal (rm -rf)"
    fi
  fi
fi

# --- git push --force detection ---
# Explicitly excludes --force-with-lease and --force-if-includes (safe alternatives)
if printf '%s' "$CMD_LOWER" | grep -qE 'git\s+push\s'; then
  if printf '%s' "$CMD_LOWER" | grep -qE '\s--force(\s|$)|\s-f(\s|$)'; then
    if ! printf '%s' "$CMD_LOWER" | grep -qE '\s--force-with-lease|\s--force-if-includes'; then
      block "Force push (git push --force)"
    fi
  fi
fi

# --- git reset --hard ---
if printf '%s' "$CMD_LOWER" | grep -qE 'git\s+reset\s+--hard'; then
  block "Destructive git operation (git reset --hard discards all uncommitted changes)"
fi

# --- git clean -fd ---
if printf '%s' "$CMD_LOWER" | grep -qE 'git\s+clean\s+-[a-z]*f[a-z]*d|git\s+clean\s+-[a-z]*d[a-z]*f'; then
  block "Destructive git operation (git clean -fd removes untracked files and directories)"
fi

# --- SQL: DROP TABLE ---
if printf '%s' "$CMD_LOWER" | grep -qE 'drop\s+table'; then
  block "Destructive SQL (DROP TABLE)"
fi

# --- SQL: TRUNCATE ---
if printf '%s' "$CMD_LOWER" | grep -qE 'truncate\s'; then
  block "Destructive SQL (TRUNCATE)"
fi

# --- SQL: DELETE FROM without WHERE ---
if printf '%s' "$CMD_LOWER" | grep -qE 'delete\s+from\s'; then
  if ! printf '%s' "$CMD_LOWER" | grep -qi 'where'; then
    block "Destructive SQL (DELETE FROM without WHERE clause)"
  fi
fi

exit 0
