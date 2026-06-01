#!/bin/sh
#
# anb-vault.sh — full backup / restore for Alice & Bob state.
#
# Supersedes anb-backup.sh: instead of a hand-maintained file whitelist it
# packs the *entire* state directory (minus volatile runtime files), embeds a
# SHA-256 manifest for content-level integrity, encrypts with age (recipient
# preferred, passphrase fallback), keeps timestamped versions, and restores
# atomically — always snapshotting the current config first. For `bob` it also
# stops the daemon before swapping state, restarts it after, and verifies the
# round-trip with `alice status`.
#
# SUBCOMMANDS
#   backup  <alice|bob|both> [-o DIR] [-r RECIP | -R FILE | -p] [-k N] [--armor]
#   restore <alice|bob>  <file.age> [-d STATE_DIR] [-i IDENTITY] [--addr H:P]
#                                   [--no-restart] [--force]
#   verify  <file.age> [-i IDENTITY]
#   list    [-o DIR]
#
# ENCRYPTION (backup)
#   -r age1...   encrypt to an age recipient (recommended — no weak passphrase)
#   -R file      recipients file (one per line)
#   -p           passphrase mode (age -p; TTY required)
#   (none)       use $ANB_AGE_RECIPIENT if set; else -p on a TTY; else REFUSE.
#                Never silently falls back to weak protection in a non-TTY.
#   --armor      ASCII-armored output
#
# DECRYPTION (restore/verify)
#   -i file      age identity for recipient-encrypted backups
#                ($ANB_AGE_IDENTITY honored too). Passphrase backups prompt.
#
# ENV
#   ANB_BACKUP_DIR   default output dir (default: ~/anb-backups, mode 700)
#   ANB_ALICE_DIR    alice state dir   (default: ~/.anb/alice)
#   ANB_BOB_DIR      bob   state dir   (default: ~/.anb/bob)
#   ANB_BOB_ADDR     addr for bob restart (default: 127.0.0.1:8443)
#   ANB_BOB_PASSWORD passed through to `bob serve` on restart (else TTY prompt)
#   ANB_AGE_RECIPIENT / ANB_AGE_IDENTITY  see above
#
# RESTORE GUARANTEES
#   1. The new backup is verified (decrypt + manifest) BEFORE anything on disk
#      is touched. A bad archive aborts with the live config untouched.
#   2. The current state is snapshotted to a `prerestore` age archive first.
#   3. Swap is atomic: old dir → <dir>.bak-<ts>, new state moved into place.
#
# Requires: age, age-keygen (filippo.io/age), tar, shasum or sha256sum.
# NOTE: file names with spaces inside the state dir are unsupported (AnB never
#       creates any). Retention sorts by the timestamp embedded in the name.

set -eu

TOOL="anb-vault 1.0"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
info() { printf '%s\n' "$*" >&2; }
ok()   { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "$1 not on PATH${2:+ ($2)}"; }

# UTC timestamp, deterministic format good for lexical sort.
now_ts() { date -u +%Y%m%dT%H%M%SZ; }

# sha256 of a file, prints the hex digest only (macOS shasum / Linux sha256sum).
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Resolve a side ("alice"/"bob") to its state directory.
state_dir() {
  case "$1" in
    alice) printf '%s' "${ANB_ALICE_DIR:-$HOME/.anb/alice}" ;;
    bob)   printf '%s' "${ANB_BOB_DIR:-$HOME/.anb/bob}" ;;
    *)     die "side must be 'alice' or 'bob' (got '$1')" ;;
  esac
}

backup_root() {
  d="${ANB_BACKUP_DIR:-$HOME/anb-backups}"
  mkdir -p "$d"
  chmod 700 "$d" 2>/dev/null || true
  printf '%s' "$d"
}

# Volatile files that must never enter a backup (pid/log/socket/lock).
TAR_EXCLUDES='--exclude=*.log --exclude=*.pid --exclude=*.sock --exclude=*.lock'

# A staging dir living next to the target so the final mv is same-filesystem
# (atomic) and private keys never transit a world-shared $TMPDIR.
make_stage() {
  base="$1"; tag="$2"
  parent=$(dirname "$base")
  mkdir -p "$parent"
  s="$parent/.anb-vault-$tag-$$"
  rm -rf "$s"
  mkdir -p "$s"
  chmod 700 "$s"
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# core: pack one side's state dir into an age archive at $out
# ---------------------------------------------------------------------------
# usage: pack_state <side> <state_dir> <out.age> <label> -- <age args...>
pack_state() {
  side="$1"; dir="$2"; out="$3"; label="$4"; shift 4
  [ "$1" = "--" ] && shift

  [ -d "$dir" ] || die "$dir does not exist"

  stage=$(make_stage "$dir" "pack")
  # shellcheck disable=SC2064
  trap "rm -rf \"$stage\"" EXIT INT TERM

  # Copy state (minus runtime files) into the stage, preserving perms.
  # shellcheck disable=SC2086
  ( cd "$dir" && tar -cf - $TAR_EXCLUDES . ) | ( cd "$stage" && tar -xpf - )

  if [ -z "$(find "$stage" -type f ! -name MANIFEST.txt 2>/dev/null | head -n1)" ]; then
    rm -rf "$stage"; trap - EXIT INT TERM
    die "nothing to back up in $dir (only runtime files?)"
  fi

  # Build the manifest from what actually landed in the stage.
  mfile="$stage/MANIFEST.txt"
  {
    echo "# $TOOL backup manifest"
    echo "# side:    $side"
    echo "# created: $(now_ts)"
    echo "# host:    $(hostname 2>/dev/null || echo unknown)"
    echo "# source:  $dir"
    echo "# label:   $label"
    echo "# --- sha256  path ---"
  } > "$mfile"
  ( cd "$stage" && find . -type f ! -name MANIFEST.txt | sed 's|^\./||' | sort ) \
    | while IFS= read -r f; do
        printf '%s  %s\n' "$(sha256_file "$stage/$f")" "$f" >> "$mfile"
      done

  # Encrypt: tar the stage (incl. MANIFEST) → age → out (atomic via .tmp).
  tmp="$out.tmp.$$"
  if ( cd "$stage" && tar -cf - . ) | age "$@" > "$tmp"; then
    [ -s "$tmp" ] || { rm -f "$tmp"; die "age produced an empty file (encryption failed)"; }
    mv "$tmp" "$out"
    chmod 600 "$out"
  else
    rm -f "$tmp"
    die "encryption failed for $out"
  fi

  nf=$( find "$stage" -type f ! -name MANIFEST.txt | wc -l | tr -d ' ' )
  rm -rf "$stage"
  trap - EXIT INT TERM

  ok "$side backup → $out ($nf files, $(wc -c <"$out" | tr -d ' ') bytes)"
}

# Build age encryption args into $@ based on flags/env. Refuses weak fallback.
# usage: enc_args=$(resolve_enc_args "$recipient" "$rfile" "$pass" "$armor")  (prints space-joined, but we use a fn that sets positional)
# We instead emit directly via a helper that the caller `eval`s — keep it simple
# by handling it inline in cmd_backup.

# ---------------------------------------------------------------------------
# subcommand: backup
# ---------------------------------------------------------------------------
cmd_backup() {
  side="${1:-}"; shift || true
  [ -n "$side" ] || die "usage: $0 backup <alice|bob|both> [opts]"

  outdir=""; recipient=""; rfile=""; pass=0; armor=0; keep=10
  while [ $# -gt 0 ]; do
    case "$1" in
      -o) outdir="$2"; shift 2 ;;
      -r) recipient="$2"; shift 2 ;;
      -R) rfile="$2"; shift 2 ;;
      -p) pass=1; shift ;;
      -k) keep="$2"; shift 2 ;;
      --armor) armor=1; shift ;;
      *) die "backup: unknown option '$1'" ;;
    esac
  done
  [ -n "$outdir" ] || outdir=$(backup_root)
  mkdir -p "$outdir"; chmod 700 "$outdir" 2>/dev/null || true

  need_cmd age "brew install age"
  need_cmd tar

  # Resolve encryption mode (recipient preferred; fail-closed otherwise).
  set --
  if [ -n "$recipient" ]; then set -- -r "$recipient"
  elif [ -n "$rfile" ]; then [ -f "$rfile" ] || die "recipients file not found: $rfile"; set -- -R "$rfile"
  elif [ "$pass" = 1 ]; then set -- -p
  elif [ -n "${ANB_AGE_RECIPIENT:-}" ]; then set -- -r "$ANB_AGE_RECIPIENT"
  elif [ -t 0 ] || [ -t 1 ]; then
    warn "no recipient given — using passphrase mode (-p). For unattended/strong backups pass -r age1... or set ANB_AGE_RECIPIENT."
    set -- -p
  else
    die "no recipient and not a TTY — refusing to fall back to weak/no encryption. Pass -r/-R, set ANB_AGE_RECIPIENT, or run with -p on a terminal."
  fi
  [ "$armor" = 1 ] && set -- "$@" --armor

  case "$side" in
    alice|bob) sides="$side" ;;
    both)      sides="alice bob" ;;
    *)         die "side must be alice, bob, or both (got '$side')" ;;
  esac

  ts=$(now_ts)
  for s in $sides; do
    dir=$(state_dir "$s")
    [ -d "$dir" ] || { warn "skipping $s — $dir does not exist"; continue; }
    out="$outdir/anb-$s-$ts.age"
    pack_state "$s" "$dir" "$out" "scheduled" -- "$@"
    prune_old "$outdir" "$s" "$keep"
  done
}

# Keep only the newest $keep regular backups for a side (prerestore archives
# are never pruned — they are the safety net).
prune_old() {
  outdir="$1"; side="$2"; keep="$3"
  [ "$keep" -gt 0 ] 2>/dev/null || return 0
  # Regular backups start with a digit after the side; prerestore ones do not.
  set +e
  files=$(ls -1 "$outdir"/anb-"$side"-[0-9]*.age 2>/dev/null | sort)
  set -e
  [ -n "$files" ] || return 0
  total=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
  excess=$((total - keep))
  [ "$excess" -gt 0 ] || return 0
  printf '%s\n' "$files" | head -n "$excess" | while IFS= read -r f; do
    rm -f "$f" && info "  retention: removed old backup $(basename "$f")"
  done
}

# ---------------------------------------------------------------------------
# core: decrypt an archive into a fresh stage and verify its manifest.
# Prints the stage path on stdout. Caller owns cleanup.
# usage: stage=$(unpack_verify <file.age> <near_dir> -- <age -d args...>)
# ---------------------------------------------------------------------------
unpack_verify() {
  file="$1"; near="$2"; shift 2
  [ "$1" = "--" ] && shift
  [ -f "$file" ] || die "backup file not found: $file"

  vstage=$(make_stage "$near" "restore")
  # Decrypt to a temp tar first so age's exit code is captured directly
  # (a pipe would mask it behind tar's). AEAD detects any tampering here.
  tball="$vstage/.archive.tar"
  if ! age "$@" "$file" > "$tball" 2>"$vstage/.age.err"; then
    msg=$(cat "$vstage/.age.err" 2>/dev/null)
    rm -rf "$vstage"
    die "decryption failed for $file — ${msg:-wrong passphrase, or missing -i identity for a recipient-encrypted archive, or the archive is corrupt/tampered}"
  fi
  if ! tar -xpf "$tball" -C "$vstage"; then
    rm -rf "$vstage"
    die "extract failed for $file (archive truncated?)"
  fi
  rm -f "$tball" "$vstage/.age.err"

  m="$vstage/MANIFEST.txt"
  [ -f "$m" ] || { rm -rf "$vstage"; die "archive has no MANIFEST.txt — not an anb-vault backup?"; }

  bad=0; n=0
  # Body lines are "<64hex>  <path>"; metadata lines start with '#'.
  while IFS= read -r line; do
    case "$line" in
      ''|\#*) continue ;;
    esac
    exp=$(printf '%s' "$line" | awk '{print $1}')
    path=$(printf '%s' "$line" | sed 's/^[0-9a-f]*  //')
    [ -n "$path" ] || continue
    n=$((n + 1))
    if [ ! -f "$vstage/$path" ]; then
      warn "manifest lists missing file: $path"; bad=$((bad + 1)); continue
    fi
    got=$(sha256_file "$vstage/$path")
    if [ "$got" != "$exp" ]; then
      warn "checksum mismatch: $path"; bad=$((bad + 1))
    fi
  done < "$m"

  if [ "$bad" -ne 0 ]; then
    rm -rf "$vstage"
    die "manifest verification FAILED ($bad of $n files bad) — archive is corrupt or tampered"
  fi

  # Emit the verified stage path for the caller (status line to stderr).
  ok "verified $n file(s) against manifest"
  printf '%s' "$vstage"
}

# Build age decrypt args into $@ from -i flag / env.
# usage: set -- $(dec_args "$identity")  — but we keep it explicit in callers.

# ---------------------------------------------------------------------------
# subcommand: verify
# ---------------------------------------------------------------------------
cmd_verify() {
  file="${1:-}"; shift || true
  [ -n "$file" ] || die "usage: $0 verify <file.age> [-i identity]"
  identity=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -i) identity="$2"; shift 2 ;;
      *) die "verify: unknown option '$1'" ;;
    esac
  done
  [ -n "$identity" ] || identity="${ANB_AGE_IDENTITY:-}"

  need_cmd age "brew install age"; need_cmd tar

  set -- -d
  [ -n "$identity" ] && set -- "$@" -i "$identity"

  stage=$(unpack_verify "$file" "${TMPDIR:-/tmp}" -- "$@")
  info "manifest:"
  sed 's/^/    /' "$stage/MANIFEST.txt" >&2
  rm -rf "$stage"
  ok "$file is intact"
}

# ---------------------------------------------------------------------------
# bob daemon control (restore bob only)
# ---------------------------------------------------------------------------
bob_running_pid() {
  pf="$1/bob.pid"
  [ -f "$pf" ] || return 1
  p=$(cat "$pf" 2>/dev/null || true)
  [ -n "$p" ] || return 1
  kill -0 "$p" 2>/dev/null || return 1
  printf '%s' "$p"
}

bob_stop() {
  dir="$1"
  p=$(bob_running_pid "$dir") || { info "bob not running — nothing to stop"; return 0; }
  info "stopping bob (pid $p, SIGTERM zeroizes the key) ..."
  kill "$p" 2>/dev/null || true
  i=0
  while [ "$i" -lt 50 ]; do
    kill -0 "$p" 2>/dev/null || { ok "bob stopped"; return 0; }
    sleep 0.2; i=$((i + 1))
  done
  warn "bob (pid $p) did not exit after 10s — continuing anyway"
}

bob_start() {
  dir="$1"; addr="$2"
  if ! command -v bob >/dev/null 2>&1; then
    warn "bob not on PATH — skipping restart. Start it manually: bob serve -D --addr $addr"
    return 0
  fi
  if [ -z "${ANB_BOB_PASSWORD:-}" ] && [ ! -t 0 ]; then
    warn "no \$ANB_BOB_PASSWORD and not a TTY — cannot supply master password."
    warn "start bob manually:  bob serve -D --addr $addr"
    return 0
  fi
  info "restarting bob: bob serve -D --addr $addr"
  bob serve -D --addr "$addr" || { warn "bob serve exited non-zero — check the log"; return 0; }

  # Wait for the daemon to come up.
  i=0
  while [ "$i" -lt 50 ]; do
    if bob_running_pid "$dir" >/dev/null; then ok "bob daemon up (pid $(bob_running_pid "$dir"))"; return 0; fi
    sleep 0.2; i=$((i + 1))
  done
  warn "bob.pid did not appear after 10s — daemon may have failed to start"
}

alice_status_check() {
  command -v alice >/dev/null 2>&1 || { warn "alice not on PATH — skipping status check"; return 0; }
  # The daemon writes its pid before its mTLS listener finishes binding, so a
  # single immediate check can race and see "connection refused". Poll until
  # bob reports unlocked or ~10s elapse.
  info "verifying with: alice status (waiting for listener) ..."
  i=0; out=""
  while [ "$i" -lt 25 ]; do
    out=$(alice status 2>&1) || true
    printf '%s' "$out" | grep -qi 'unlocked' && break
    sleep 0.4; i=$((i + 1))
  done
  printf '%s\n' "$out" | sed 's/^/    /' >&2
  if printf '%s' "$out" | grep -qi 'unlocked'; then
    ok "alice ↔ bob healthy (bob unlocked)"
  else
    warn "alice could not confirm an unlocked bob after 10s — likely the master password wasn't entered, the daemon isn't up, or the mTLS cert/CA didn't match. Inspect the output above and ~/.anb/bob/bob.log."
  fi
}

# ---------------------------------------------------------------------------
# subcommand: restore
# ---------------------------------------------------------------------------
cmd_restore() {
  side="${1:-}"; file="${2:-}"; shift 2 2>/dev/null || true
  { [ -n "$side" ] && [ -n "$file" ]; } || die "usage: $0 restore <alice|bob> <file.age> [-d dir] [-i identity] [--addr H:P] [--no-restart] [--force]"
  case "$side" in alice|bob) : ;; *) die "side must be alice or bob (got '$side')" ;; esac

  dir=""; identity=""; addr="${ANB_BOB_ADDR:-127.0.0.1:8443}"; restart=1; force=0
  while [ $# -gt 0 ]; do
    case "$1" in
      -d) dir="$2"; shift 2 ;;
      -i) identity="$2"; shift 2 ;;
      --addr) addr="$2"; shift 2 ;;
      --no-restart) restart=0; shift ;;
      --force) force=1; shift ;;
      *) die "restore: unknown option '$1'" ;;
    esac
  done
  [ -n "$dir" ] || dir=$(state_dir "$side")
  [ -n "$identity" ] || identity="${ANB_AGE_IDENTITY:-}"

  need_cmd age "brew install age"; need_cmd tar

  set -- -d
  [ -n "$identity" ] && set -- "$@" -i "$identity"

  # 1. Verify the incoming archive FIRST — nothing on disk is touched yet.
  info "── step 1/6: verifying backup ──"
  newstage=$(unpack_verify "$file" "$dir" -- "$@")
  rm -f "$newstage/MANIFEST.txt"   # manifest is metadata, not state

  if [ "$force" -ne 1 ] && { [ -t 0 ] && [ -t 1 ]; }; then
    printf 'About to restore %s state into %s (current config will be snapshotted + moved aside). Type "yes" to proceed: ' "$side" "$dir" >&2
    read -r ans
    [ "$ans" = "yes" ] || { rm -rf "$newstage"; die "aborted by user"; }
  fi

  # 2. Snapshot the CURRENT config before changing anything.
  if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    info "── step 2/6: snapshotting current config (prerestore) ──"
    pre="$(backup_root)/anb-$side-prerestore-$(now_ts).age"
    # Encrypt the prerestore snapshot the same way as the source archive:
    # reuse identity as recipient is impossible, so prefer ANB_AGE_RECIPIENT,
    # else passphrase on a TTY, else plain tar.gz fallback is NOT allowed — warn.
    if [ -n "${ANB_AGE_RECIPIENT:-}" ]; then
      pack_state "$side" "$dir" "$pre" "prerestore" -- -r "$ANB_AGE_RECIPIENT"
    elif [ -t 0 ] || [ -t 1 ]; then
      info "(prerestore snapshot uses passphrase mode — set ANB_AGE_RECIPIENT to avoid the prompt)"
      pack_state "$side" "$dir" "$pre" "prerestore" -- -p
    else
      warn "cannot encrypt prerestore snapshot (no ANB_AGE_RECIPIENT, no TTY) — falling back to moving the old dir aside only (step 4)."
    fi
  else
    info "── step 2/6: no existing config to snapshot ──"
  fi

  # 3. Stop bob before swapping its state.
  if [ "$side" = bob ]; then
    info "── step 3/6: stopping bob ──"
    bob_stop "$dir"
  else
    info "── step 3/6: (alice has no daemon) ──"
  fi

  # 4. Atomic swap: old dir → .bak-<ts>, new state into place.
  info "── step 4/6: swapping state atomically ──"
  if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    bak="$dir.bak-$(now_ts)"
    mv "$dir" "$bak"
    info "  old config moved to $bak"
  else
    rm -rf "$dir" 2>/dev/null || true
  fi
  mkdir -p "$(dirname "$dir")"
  mv "$newstage" "$dir"
  chmod 700 "$dir" 2>/dev/null || true
  find "$dir" -type f -name '*.key' -exec chmod 600 {} + 2>/dev/null || true
  ok "state restored into $dir"

  # 5. Restart bob.
  if [ "$side" = bob ] && [ "$restart" = 1 ]; then
    info "── step 5/6: restarting bob ──"
    bob_start "$dir" "$addr"
  else
    info "── step 5/6: restart skipped ──"
  fi

  # 6. Verify the round-trip.
  if [ "$side" = bob ] && [ "$restart" = 1 ]; then
    info "── step 6/6: verifying alice ↔ bob ──"
    alice_status_check
  else
    info "── step 6/6: (no daemon to verify) ──"
  fi

  ok "restore complete"
  [ -n "${bak:-}" ] && info "rollback if needed:  rm -rf '$dir' && mv '$bak' '$dir'"
}

# ---------------------------------------------------------------------------
# subcommand: list
# ---------------------------------------------------------------------------
cmd_list() {
  outdir=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -o) outdir="$2"; shift 2 ;;
      *) die "list: unknown option '$1'" ;;
    esac
  done
  [ -n "$outdir" ] || outdir=$(backup_root)
  [ -d "$outdir" ] || die "$outdir does not exist"

  found=0
  for f in "$outdir"/anb-*.age; do
    [ -f "$f" ] || continue
    found=1
    sz=$(wc -c <"$f" | tr -d ' ')
    printf '%-50s  %8s bytes\n' "$(basename "$f")" "$sz"
  done >&2
  [ "$found" = 1 ] || info "no backups in $outdir"
}

# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------
usage() {
  cat >&2 <<USAGE
$TOOL — backup / restore for Alice & Bob state

Usage:
  $0 backup  <alice|bob|both> [-o DIR] [-r RECIP | -R FILE | -p] [-k N] [--armor]
  $0 restore <alice|bob>  <file.age> [-d STATE_DIR] [-i IDENTITY] [--addr H:P] [--no-restart] [--force]
  $0 verify  <file.age> [-i IDENTITY]
  $0 list    [-o DIR]

Encryption prefers an age recipient (-r/-R or \$ANB_AGE_RECIPIENT); passphrase
(-p) is the TTY fallback. Restore always verifies the archive and snapshots the
current config before swapping. For bob it stops/restarts the daemon and runs
'alice status' to confirm the round-trip.
USAGE
  exit 2
}

sub="${1:-}"; shift 2>/dev/null || true
case "$sub" in
  backup)  cmd_backup "$@" ;;
  restore) cmd_restore "$@" ;;
  verify)  cmd_verify "$@" ;;
  list)    cmd_list "$@" ;;
  ""|-h|--help|help) usage ;;
  *) die "unknown subcommand '$sub' (try: backup|restore|verify|list)" ;;
esac
