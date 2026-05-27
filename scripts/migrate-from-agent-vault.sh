#!/usr/bin/env bash
#
# migrate-from-agent-vault.sh — move secrets from agent-vault into AnB (alice/bob).
#
# What it does:
#   1. Reads key names (NOT values) from `agent-vault list --json`.
#   2. Bulk-migrates non-presence keys: builds a placeholder template, has
#      agent-vault restore real values into a temp file, then `alice import`s it.
#      The temp file is overwritten (`rm -P`) immediately after.
#   3. Migrates presence-gated keys interactively (`alice set --require-presence`)
#      so their plaintext never touches disk — you paste them at the prompt.
#   4. Verifies the result with `alice list`.
#
# Why it's shaped this way (hard-won quirks):
#   - `agent-vault get --reveal | alice set --stdin` does NOT work: both tools
#     refuse when stdout is a pipe (anti-exfiltration gate). Hence the temp-file
#     route via `agent-vault write`, which restores <agent-vault:key> placeholders.
#   - `alice import` key mapping: the .env left-hand side must match
#     [A-Za-z_][A-Za-z0-9_]*, is lowercased, and '_' -> '-'. agent-vault keys are
#     lower-kebab with no underscores, so we map '-' -> '_' on the LHS and import
#     maps it back exactly. Keys starting with a digit can't round-trip and are
#     reported for manual handling.
#   - import's default --min-length 8 silently skips short values (e.g. an SMTP
#     port "587"); we pass --min-length 1.
#   - import does NOT carry over a presence flag, which is the other reason
#     presence-gated keys go the interactive route (where --require-presence sets it).
#
# Requires: agent-vault, alice (on PATH), jq, and Bob already serving + unlocked.
# This script migrates only; it does NOT uninstall or delete agent-vault.
#
# Usage:
#   scripts/migrate-from-agent-vault.sh            # run the migration
#   scripts/migrate-from-agent-vault.sh --dry-run  # show the plan, touch nothing
#   scripts/migrate-from-agent-vault.sh --min-length N   # override (default 1)

set -euo pipefail

DRY_RUN=0
MINLEN=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)    DRY_RUN=1; shift ;;
    --min-length) MINLEN="${2:?--min-length needs a number}"; shift 2 ;;
    -h|--help)    sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then
  c_ok=$'\033[32m'; c_warn=$'\033[33m'; c_err=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
else
  c_ok=''; c_warn=''; c_err=''; c_dim=''; c_off=''
fi
info() { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$c_ok" "$c_off" "$*"; }
warn() { printf '%s⚠%s %s\n' "$c_warn" "$c_off" "$*"; }
die()  { printf '%s✗%s %s\n' "$c_err" "$c_off" "$*" >&2; exit 1; }

# --- preconditions ---------------------------------------------------------
for bin in agent-vault alice jq; do
  command -v "$bin" >/dev/null 2>&1 || die "'$bin' not found on PATH"
done
if ! alice status 2>/dev/null | grep -q 'unlocked'; then
  die "Bob is not reachable/unlocked. Start it first:  bob serve --addr 127.0.0.1:8443"
fi

# --- enumerate keys (names only; never values) -----------------------------
# (bash 3.2 compatible: no mapfile, no bare empty-array expansion under set -u)
LIST_JSON="$(agent-vault list --json)"

IMPORTABLE=()   # non-presence keys expressible as a .env LHS
SKIP=()         # non-presence keys that can't round-trip (e.g. digit-leading)
while IFS= read -r k; do
  [[ -z "$k" ]] && continue
  envkey="${k//-/_}"
  if [[ "$envkey" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    IMPORTABLE+=("$k")
  else
    SKIP+=("$k")
  fi
done < <(jq -r '.keys[] | select(.requirePresence != true) | .key' <<<"$LIST_JSON")

PRESENCE_KEYS=()
while IFS= read -r k; do
  [[ -n "$k" ]] && PRESENCE_KEYS+=("$k")
done < <(jq -r '.keys[] | select(.requirePresence == true) | .key' <<<"$LIST_JSON")

# --- plan ------------------------------------------------------------------
info "${c_dim}agent-vault → AnB migration plan${c_off}"
info "  bulk (temp-file import, --min-length $MINLEN): ${#IMPORTABLE[@]}"
if ((${#IMPORTABLE[@]})); then for k in "${IMPORTABLE[@]}"; do info "    $k"; done; fi
info "  presence-gated (interactive, never on disk):  ${#PRESENCE_KEYS[@]}"
if ((${#PRESENCE_KEYS[@]})); then for k in "${PRESENCE_KEYS[@]}"; do info "    $k  [presence]"; done; fi
if ((${#SKIP[@]})); then
  warn "cannot auto-migrate (handle manually with: alice set <key>): ${#SKIP[@]}"
  for k in "${SKIP[@]}"; do info "    $k"; done
fi

if ((DRY_RUN)); then
  info "${c_dim}--dry-run: nothing was changed.${c_off}"
  exit 0
fi

# --- secure temp dir (best-effort overwrite on exit) -----------------------
TMPD="$(mktemp -d "${TMPDIR:-/tmp}/anb-migrate.XXXXXX")"
chmod 700 "$TMPD"
MIGFILE="$TMPD/migrate.env"
cleanup() {
  [[ -f "$MIGFILE" ]] && rm -Pf "$MIGFILE" 2>/dev/null || true
  rm -rf "$TMPD" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
# For zero SSD residue, point TMPDIR at a RAM disk before running this script.

# --- bulk migration --------------------------------------------------------
if ((${#IMPORTABLE[@]})); then
  TEMPLATE="$TMPD/template.env"   # placeholders only — contains no secrets
  : >"$TEMPLATE"
  for k in "${IMPORTABLE[@]}"; do
    printf '%s=<agent-vault:%s>\n' "${k//-/_}" "$k" >>"$TEMPLATE"
  done
  # agent-vault write reads stdin, restores placeholders, writes to MIGFILE.
  agent-vault write "$MIGFILE" <"$TEMPLATE"
  info "${c_dim}importing ${#IMPORTABLE[@]} keys into AnB (confirm at the prompt)…${c_off}"
  alice import "$MIGFILE" --min-length "$MINLEN"
  rm -Pf "$MIGFILE"
  ok "bulk keys imported"
fi

# --- presence-gated migration (interactive, no disk) -----------------------
if ((${#PRESENCE_KEYS[@]})); then for k in "${PRESENCE_KEYS[@]}"; do
  info ""
  info "${c_warn}presence-gated:${c_off} $k — migrate interactively (value stays off disk)"
  info "  current value from agent-vault (may prompt Touch ID):"
  agent-vault get "$k" --reveal || { warn "could not reveal $k; skipping"; continue; }
  info "  now paste it into AnB:"
  alice set "$k" --require-presence --reason "migrated from agent-vault"
done; fi

# --- verify ----------------------------------------------------------------
info ""
ok "migration finished — current AnB keys:"
alice list
info ""
info "${c_dim}Next: spot-check a value (alice get <key> --reveal vs agent-vault get <key> --reveal),"
info "then decommission agent-vault once nothing still depends on it.${c_off}"
