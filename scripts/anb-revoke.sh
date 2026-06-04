#!/usr/bin/env bash
#
# anb-revoke.sh — the "a secret leaked, really kill it" one-shot.
#
# AnB has no per-secret key: the only HARD revocation is at the master-key
# layer. `alice set`/`alice rm` just rewrite vault.json, and since vault.json
# has no freshness marker an old copy can be rolled back into place to
# resurrect a leaked value. Destroying the old master-key version is what
# actually kills it — an old vault.json becomes undecryptable bytes.
#
# This script runs the full, order-sensitive dance so you don't have to:
#
#   1. bob rotate-master-key            (new current K; old K kept for now)
#   2. restart bob serve                (daemon must reload to HOLD the new K)
#   3. alice rekey                      (migrate every vault entry onto new K)
#   4. alice rekey-status  == 0 on old  (GATE: refuse to finalize otherwise)
#   5. bob rotate-master-key --finalize <old>   (destroy each old K)
#   6. restart bob serve                (drop old K from daemon memory)
#   7. verify                           (only the new K remains; vault loads)
#
# The two restarts are NOT optional: step 1 only writes envelope.json — the
# running daemon keeps its old in-memory K until restarted, so rekey (step 3)
# would otherwise migrate onto the OLD current and step 5 would brick entries.
# The step-4 gate is the brick-stopper: if any entry is still on an old K
# (e.g. a second enrolled identity you didn't rekey), the script aborts BEFORE
# destroying anything.
#
# Run it in a real terminal: `alice rekey` requires a TTY, and you'll be asked
# for the master password once (held in-process for the run; on macOS another
# process can't read it from your environment). For automation/testing set
# $ANB_BOB_PASSWORD to skip the prompt.
#
# Usage:
#   scripts/anb-revoke.sh [--addr HOST:PORT] [--bob-dir DIR] [--alice-dir DIR] [--yes]
#
# After it finishes: `alice set <leaked-key>` the NEW credential value, and
# restart any service that injects secrets at launch (e.g. kind-reminder).

set -euo pipefail

ADDR="127.0.0.1:8443"
BOB_DIR="${ANB_BOB_DIR:-$HOME/.anb/bob}"
ALICE_DIR=""              # empty → alice's own default (~/.anb/alice)
ASSUME_YES=0
BOB_BIN="${BOB_BIN:-$(command -v bob || true)}"
ALICE_BIN="${ALICE_BIN:-$(command -v alice || true)}"

while [ $# -gt 0 ]; do
  case "$1" in
    --addr)      ADDR="$2"; shift 2 ;;
    --bob-dir)   BOB_DIR="$2"; shift 2 ;;
    --alice-dir) ALICE_DIR="$2"; shift 2 ;;
    --yes|-y)    ASSUME_YES=1; shift ;;
    -h|--help)   sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "anb-revoke: unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BOB_BIN" ]   || { echo "anb-revoke: 'bob' not found in PATH (set \$BOB_BIN)" >&2; exit 2; }
[ -n "$ALICE_BIN" ] || { echo "anb-revoke: 'alice' not found in PATH (set \$ALICE_BIN)" >&2; exit 2; }

# --dir is a per-subcommand flag, not global (`bob ca init --dir X`, not
# `bob --dir X ca init`). Pass state dirs via env instead — both binaries
# honor $ANB_BOB_DIR / $ANB_ALICE_DIR, and daemonized children inherit them.
export ANB_BOB_DIR="$BOB_DIR"
[ -n "$ALICE_DIR" ] && export ANB_ALICE_DIR="$ALICE_DIR"
bob_()   { "$BOB_BIN"   "$@"; }
alice_() { "$ALICE_BIN" "$@"; }

PID_FILE="$BOB_DIR/bob.pid"

die() { echo "✗ anb-revoke: $*" >&2; exit 1; }
log() { echo "→ $*" >&2; }

# --- preflight ---------------------------------------------------------------
[ -f "$BOB_DIR/envelope.json" ] || die "no envelope.json in $BOB_DIR — is this the right --bob-dir?"

# Master password: env if set (automation), else prompt once and hold it.
if [ -z "${ANB_BOB_PASSWORD:-}" ]; then
  [ -t 0 ] || die "no TTY and \$ANB_BOB_PASSWORD unset — can't get the master password"
  printf 'Master password: ' >&2
  read -rs ANB_BOB_PASSWORD; echo >&2
  [ -n "$ANB_BOB_PASSWORD" ] || die "empty password"
fi
export ANB_BOB_PASSWORD
# Best-effort scrub on exit.
trap 'unset ANB_BOB_PASSWORD 2>/dev/null || true' EXIT

# Parse `bob list-keys`: ID is column 1; the current row carries a "←".
current_kid() { bob_ list-keys | awk 'NR>1 && /←/ {print $1; exit}'; }
all_kids()    { bob_ list-keys | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}'; }

OLD_KID="$(current_kid || true)"
[ -n "$OLD_KID" ] || die "couldn't read the current K id from 'bob list-keys'"

# Count vault entries up front so we can sanity-check the rekey later.
N_ENTRIES="$(alice_ rekey-status | awk '$1=="total"{print $2}')"
log "current master key: K_$OLD_KID; vault entries: ${N_ENTRIES:-?}"

if [ "$ASSUME_YES" -ne 1 ]; then
  cat >&2 <<EOF

This will ROTATE the master key, migrate the vault onto the new key, and then
DESTROY the old key (K_$OLD_KID). After it completes, any old/rolled-back copy
of vault.json becomes permanently undecryptable.

  bob dir:   $BOB_DIR
  alice dir: ${ALICE_DIR:-(alice default ~/.anb/alice)}
  daemon:    $ADDR

NOTE: this rekeys only THIS alice. If you have other enrolled identities with
vault entries, rekey them before their old-K entries get bricked.
EOF
  printf "Type 'yes' to proceed: " >&2
  read -r reply; [ "$reply" = "yes" ] || die "cancelled — nothing changed"
fi

# --- mandatory backup --------------------------------------------------------
TS="$(date +%Y%m%dT%H%M%S)"
cp "$BOB_DIR/envelope.json" "$BOB_DIR/envelope.json.pre-revoke-$TS"
log "backed up envelope.json → envelope.json.pre-revoke-$TS"
VAULT_JSON="${ALICE_DIR:-$HOME/.anb/alice}/vault.json"
if [ -f "$VAULT_JSON" ]; then
  cp "$VAULT_JSON" "$VAULT_JSON.pre-revoke-$TS"
  log "backed up vault.json → $(basename "$VAULT_JSON").pre-revoke-$TS"
fi

# --- daemon restart helper ---------------------------------------------------
stop_daemon() {
  if [ -f "$PID_FILE" ]; then
    local pid; pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    fi
  fi
}
start_daemon() {
  # -D detaches; the child prunes ANB_BOB_PASSWORD from its own env on read.
  bob_ serve -D --addr "$ADDR"
  # Poll until alice sees an unlocked bob (≈ up to 10s).
  for _ in $(seq 1 50); do
    if alice_ status 2>/dev/null | grep -qi 'unlock'; then return 0; fi
    sleep 0.2
  done
  die "daemon did not come up unlocked on $ADDR (check $BOB_DIR/bob.log)"
}
restart_daemon() { stop_daemon; start_daemon; }

# --- 1. rotate ---------------------------------------------------------------
log "1/7 rotate-master-key (adding a fresh current K)"
bob_ rotate-master-key >/dev/null || die "rotate-master-key failed (wrong password?) — envelope unchanged"
NEW_KID="$(current_kid || true)"
[ -n "$NEW_KID" ] && [ "$NEW_KID" != "$OLD_KID" ] || die "rotation did not advance the current K id"
log "    new current master key: K_$NEW_KID"

# --- 2. restart so the daemon HOLDS the new K --------------------------------
log "2/7 restart bob serve (load new K into memory)"
restart_daemon

# --- 3. rekey (migrate vault onto the new K) ---------------------------------
log "3/7 alice rekey (migrate every entry onto K_$NEW_KID)"
alice_ rekey || die "alice rekey failed — old K still intact, nothing destroyed"

# --- 4. GATE: nothing may remain on a non-current K --------------------------
log "4/7 verify rekey-status (gate before destroying old keys)"
STALE="$(alice_ rekey-status | awk -v cur="v$NEW_KID" '
  NR>1 && ($1 ~ /^v/ || $1=="(malformed)") && $1!=cur && $1!="total" {s+=$2}
  END{print s+0}')"
[ "$STALE" = "0" ] || die "$STALE vault entr(y/ies) still NOT on K_$NEW_KID — refusing to finalize (would brick them). Rekey all identities first; nothing destroyed."

# --- 5. finalize every old K -------------------------------------------------
log "5/7 finalize old key version(s)"
for kid in $(all_kids); do
  [ "$kid" = "$NEW_KID" ] && continue
  log "    destroying K_$kid"
  bob_ rotate-master-key --finalize "$kid" --yes >/dev/null || die "finalize K_$kid failed"
done

# --- 6. restart so the daemon drops the old K from memory --------------------
log "6/7 restart bob serve (drop old K from memory)"
restart_daemon

# --- 7. verify ---------------------------------------------------------------
log "7/7 verify"
REMAIN="$(all_kids | tr '\n' ' ')"
echo "$REMAIN" | grep -qw "$NEW_KID" || die "post-check: new K_$NEW_KID missing from envelope?!"
for kid in $REMAIN; do
  [ "$kid" = "$NEW_KID" ] || die "post-check: K_$kid still present after finalize"
done
alice_ status 2>/dev/null | grep -qi 'unlock' || die "post-check: bob not unlocked"

cat >&2 <<EOF

✓ Revocation complete.
  • Master key rotated K_$OLD_KID → K_$NEW_KID; K_$OLD_KID destroyed.
  • Any old/rolled-back vault.json is now undecryptable.
  • Backups: $BOB_DIR/envelope.json.pre-revoke-$TS
$( [ -f "$VAULT_JSON.pre-revoke-$TS" ] && echo "             $VAULT_JSON.pre-revoke-$TS" )

Next:
  1. Set the NEW value of the leaked secret:   alice set <key> ...
  2. Restart services that inject secrets at launch (e.g. kind-reminder).
EOF
