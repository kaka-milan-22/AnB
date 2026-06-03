#!/bin/sh
#
# dotfiles-backup.sh — scan / backup / restore / list your dotfiles + claude
# skills as a single age-encrypted tarball. Sibling of anb-vault.sh: same age +
# tar model, no chezmoi, no lock-in (restore is plain `age -d | tar -x`).
#
#   dotfiles-backup.sh scan
#   dotfiles-backup.sh backup  [-o DIR] [-r RECIP|-R FILE|-p] [-k N] [--upload REMOTE] [--force]
#   dotfiles-backup.sh restore <file.age> [-i IDENTITY] [-C DIR]
#   dotfiles-backup.sh list    [-o DIR]
#
# Encryption prefers an age recipient ($ANB_AGE_RECIPIENT / -r / -R); passphrase
# (-p) is the TTY fallback; refuses to fall back silently in a non-TTY.
# Restore decrypts with -i / $ANB_AGE_IDENTITY (passphrase backups prompt) and
# extracts to a NEW dir (never overwrites $HOME) — you copy into place yourself.
#
# Edit PATHS below to change what gets backed up.
#
set -eu

# ---- what to back up (paths relative to $HOME) -----------------------------
PATHS="
.zshrc
.zprofile
.gitconfig
.tmux.conf
.claude/skills
.config/git
.config/gh
"

# ---- junk excluded from the tarball (tar syntax) ---------------------------
TAR_EXCLUDES="--exclude=*.log --exclude=*.pyc --exclude=__pycache__ --exclude=*.tar.gz --exclude=.DS_Store --exclude=.git"

OUTDIR_DEFAULT="$HOME/dotfiles-backups"
KEEP_DEFAULT=10

die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
ok()   { printf '\033[32m✓ %s\033[0m\n' "$*" >&2; }
info() { printf '%s\n' "$*" >&2; }
now_ts() { date -u +%Y%m%dT%H%M%SZ; }

# tar_safe <tarball> — succeed only if NO archive member is an absolute path
# or contains a ".." component. Without this, a crafted archive could write
# outside -C <dest> via "../" — defeating the "never touches $HOME" promise.
# Archives this script produces use relative paths, so they always pass.
tar_safe() {
  unsafe=$(tar -tf "$1" 2>/dev/null | LC_ALL=C awk '/^\// || /(^|\/)\.\.(\/|$)/ { print }')
  [ -z "$unsafe" ]
}

present_paths() {
  for p in $PATHS; do
    if [ -e "$HOME/$p" ]; then printf '%s\n' "$p"; fi
  done
  return 0
}

# find real files under a path, skipping junk (find syntax, NOT tar's)
find_files() {
  find "$HOME/$1" -type f \
    ! -name '*.pyc' ! -name '*.log' ! -name '*.tar.gz' \
    ! -path '*/__pycache__/*' ! -path '*/.git/*' 2>/dev/null
}

# ---- danger scan: sets global SCAN_HARD (count of hard findings) -----------
# Always returns 0 so `set -e` never aborts mid-scan; callers read SCAN_HARD.
SCAN_HARD=0
scan() {
  SCAN_HARD=0
  info "── files that would be packed ──"
  for p in $(present_paths); do
    n=$(find_files "$p" | wc -l | tr -d ' ')
    printf '  %-26s %s file(s)\n' "$p" "$n" >&2
  done

  info ""
  info "── DANGER scan ──"
  # 1. secret-format CONTENT (real key material / JWTs). age keys are UPPERCASE.
  hits=""
  for p in $(present_paths); do
    h=$(find_files "$p" | while IFS= read -r f; do
          grep -IlE -e 'AGE-SECRET-KEY-1[0-9A-Za-z]' \
                    -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
                    -e 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.' "$f" 2>/dev/null || true
        done)
    if [ -n "$h" ]; then hits="$hits$h
"; fi
  done
  hits=$(printf '%s' "$hits" | sed '/^$/d')
  if [ -n "$hits" ]; then
    warn "secret-format content in:"; printf '%s\n' "$hits" | sed 's|^|    |' >&2
    SCAN_HARD=$((SCAN_HARD + $(printf '%s\n' "$hits" | wc -l | tr -d ' ')))
  fi
  # 2. dangerous FILENAMES
  names=""
  for p in $(present_paths); do
    nf=$(find "$HOME/$p" -type f \( -name '*.key' -o -name '*.pem' -o -name 'id_rsa' \
        -o -name 'id_ed25519' -o -name '.netrc' \) 2>/dev/null || true)
    if [ -n "$nf" ]; then names="$names$nf
"; fi
  done
  names=$(printf '%s' "$names" | sed '/^$/d')
  if [ -n "$names" ]; then
    warn "key/credential files:"; printf '%s\n' "$names" | sed 's|^|    |' >&2
    SCAN_HARD=$((SCAN_HARD + $(printf '%s\n' "$names" | wc -l | tr -d ' ')))
  fi
  # 3. SOFT: large files (>1MB)
  big=""
  for p in $(present_paths); do
    b=$(find "$HOME/$p" -type f -size +1M ! -path '*/.git/*' 2>/dev/null || true)
    if [ -n "$b" ]; then big="$big$b
"; fi
  done
  big=$(printf '%s' "$big" | sed '/^$/d')
  if [ -n "$big" ]; then warn "large files (>1MB) — review:"; printf '%s\n' "$big" | sed 's|^|    |' >&2; fi

  info ""
  if [ "$SCAN_HARD" -eq 0 ]; then ok "no secret-format content, no key files — safe to back up"
  else warn "$SCAN_HARD hard finding(s) — move these secrets into AnB, don't pack them"; fi
  return 0
}

# keep only the newest $keep backups; older ones are pruned
prune_old() {
  outdir="$1"; keep="$2"
  [ "$keep" -gt 0 ] 2>/dev/null || return 0
  files=$(ls -1 "$outdir"/dotfiles-*.age 2>/dev/null | sort || true)
  [ -n "$files" ] || return 0
  total=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
  excess=$((total - keep))
  [ "$excess" -gt 0 ] || return 0
  printf '%s\n' "$files" | head -n "$excess" | while IFS= read -r f; do
    rm -f "$f" && info "  retention: removed $(basename "$f")"
  done
}

# ---- backup ----------------------------------------------------------------
cmd_backup() {
  outdir=""; recipient=""; rfile=""; pass=0; upload=""; force=0; keep="$KEEP_DEFAULT"
  while [ $# -gt 0 ]; do case "$1" in
    -o) outdir="$2"; shift 2;;
    -r) recipient="$2"; shift 2;;
    -R) rfile="$2"; shift 2;;
    -p) pass=1; shift;;
    -k) keep="$2"; shift 2;;
    --upload) upload="$2"; shift 2;;
    --force) force=1; shift;;
    *) die "backup: unknown option '$1'";;
  esac; done
  [ -n "$outdir" ] || outdir="$OUTDIR_DEFAULT"
  mkdir -p "$outdir"; chmod 700 "$outdir" 2>/dev/null || true
  command -v age >/dev/null 2>&1 || die "age not on PATH (brew install age)"

  scan
  if [ "${SCAN_HARD:-0}" -ne 0 ]; then
    [ "$force" = 1 ] || die "danger scan found hard issues above — fix them, or re-run with --force"
    warn "proceeding despite findings (--force)"
  fi

  set --
  if   [ -n "$recipient" ]; then set -- -r "$recipient"
  elif [ -n "$rfile" ]; then [ -f "$rfile" ] || die "no such recipients file: $rfile"; set -- -R "$rfile"
  elif [ "$pass" = 1 ]; then set -- -p
  elif [ -n "${ANB_AGE_RECIPIENT:-}" ]; then set -- -r "$ANB_AGE_RECIPIENT"
  elif [ -t 0 ] || [ -t 1 ]; then warn "no recipient — using passphrase mode (-p)"; set -- -p
  else die "no recipient and not a TTY — refusing to fall back to weak encryption"
  fi

  paths=$(present_paths); [ -n "$paths" ] || die "nothing to back up"
  out="$outdir/dotfiles-$(now_ts).age"; tmp="$out.tmp.$$"
  # shellcheck disable=SC2086
  if ( cd "$HOME" && tar -cf - $TAR_EXCLUDES $paths ) | age "$@" > "$tmp"; then
    [ -s "$tmp" ] || { rm -f "$tmp"; die "age produced empty output"; }
    mv "$tmp" "$out"; chmod 600 "$out"
  else rm -f "$tmp"; die "encryption failed"; fi
  ok "backup → $out ($(wc -c <"$out" | tr -d ' ') bytes)"
  prune_old "$outdir" "$keep"

  if [ -n "$upload" ]; then
    command -v rclone >/dev/null 2>&1 || die "rclone not on PATH"
    dest="$upload/$(date -u +%Y-%m-%d)"
    info "uploading to $dest/ ..."
    rclone copy "$out" "$dest/" && ok "uploaded → $dest/$(basename "$out")"
  fi
}

# ---- restore (to a fresh dir, never clobbers $HOME) ------------------------
cmd_restore() {
  file="${1:-}"; shift 2>/dev/null || true
  [ -n "$file" ] || die "usage: restore <file.age> [-i identity] [-C dir]"
  identity=""; dest=""
  while [ $# -gt 0 ]; do case "$1" in
    -i) identity="$2"; shift 2;;
    -C) dest="$2"; shift 2;;
    *) die "restore: unknown option '$1'";;
  esac; done
  [ -n "$identity" ] || identity="${ANB_AGE_IDENTITY:-}"
  [ -n "$dest" ] || dest="./dotfiles-restored-$(now_ts)"
  [ -f "$file" ] || die "not found: $file"
  command -v age >/dev/null 2>&1 || die "age not on PATH"
  mkdir -p "$dest"
  set -- -d; [ -n "$identity" ] && set -- "$@" -i "$identity"
  # Decrypt to a temp tarball first so we can validate member paths BEFORE
  # extracting — a streamed `age | tar -x` would commit the write before we
  # could reject a path-traversal archive.
  tmptar="$dest/.archive.tar"
  if ! age "$@" "$file" > "$tmptar" 2>/dev/null; then
    rm -f "$tmptar"; die "decrypt failed (wrong -i identity or passphrase?)"
  fi
  if ! tar_safe "$tmptar"; then
    rm -f "$tmptar"; die "refusing to extract $file: archive has absolute or '..' paths (possible path-traversal attack)"
  fi
  if tar -xpf "$tmptar" -C "$dest"; then
    rm -f "$tmptar"
    ok "restored → $dest"
    info "review it, then copy what you want into place yourself (it did NOT touch \$HOME)"
  else
    rm -f "$tmptar"; die "extract failed (archive truncated?)"
  fi
}

# ---- list ------------------------------------------------------------------
cmd_list() {
  outdir=""
  while [ $# -gt 0 ]; do case "$1" in
    -o) outdir="$2"; shift 2;;
    *) die "list: unknown option '$1'";;
  esac; done
  [ -n "$outdir" ] || outdir="$OUTDIR_DEFAULT"
  [ -d "$outdir" ] || die "$outdir does not exist"
  found=0
  for f in "$outdir"/dotfiles-*.age; do
    [ -f "$f" ] || continue
    found=1
    printf '%-46s %9s bytes\n' "$(basename "$f")" "$(wc -c <"$f" | tr -d ' ')"
  done >&2
  [ "$found" = 1 ] || info "no backups in $outdir"
}

sub="${1:-}"; shift 2>/dev/null || true
case "$sub" in
  scan)    scan; [ "${SCAN_HARD:-0}" -eq 0 ] || exit 1;;
  backup)  cmd_backup "$@";;
  restore) cmd_restore "$@";;
  list)    cmd_list "$@";;
  ""|-h|--help) cat >&2 <<EOF
dotfiles-backup.sh — age-encrypted backup of dotfiles + claude skills

  scan                              list packable files + flag dangerous ones
  backup [-o DIR] [-r REC|-R F|-p] [-k N] [--upload REMOTE] [--force]
  restore <file.age> [-i IDENTITY] [-C DIR]
  list [-o DIR]

Examples:
  dotfiles-backup.sh scan
  ANB_AGE_RECIPIENT=age1... dotfiles-backup.sh backup --upload gdrive:dotfiles-backup
  ANB_AGE_IDENTITY=~/key.txt dotfiles-backup.sh restore ~/dotfiles-backups/dotfiles-....age
EOF
    exit 2;;
  *) die "unknown subcommand '$sub' (scan|backup|restore|list)";;
esac
