#!/bin/sh
#
# anb-backup.sh — pack alice or bob state into an age-encrypted tarball.
#
# Restore is just standard age + tar (no helper needed):
#
#     mkdir -p ~/.anb/alice && age -d alice.age | tar -C ~/.anb/alice -xf -
#
# Examples:
#     scripts/anb-backup.sh alice ~/bkp/alice.age              # passphrase (default)
#     scripts/anb-backup.sh alice ~/bkp/alice.age -p --armor   # passphrase, ASCII-armored
#     scripts/anb-backup.sh bob   ~/bkp/bob.age   -r age1xxxx  # to an age recipient
#
# Anything after <out.age> is forwarded to `age` so you can mix -p / -r /
# --armor / -R recipients-file etc. With no extra args the script
# defaults to passphrase mode (`age -p`). Output is chmod'd 0600.
#
# Requires: age (filippo.io/age — `brew install age`), tar.

set -eu

side=${1:-}
out=${2:-}

case "$side" in
  alice)
    files="vault.json client.key client.crt ca.crt config.json exec-allowlist.json"
    dir="${ANB_ALICE_DIR:-$HOME/.anb/alice}"
    ;;
  bob)
    files="ca.crt ca.key server.crt server.key envelope.json authz.json"
    dir="${ANB_BOB_DIR:-$HOME/.anb/bob}"
    ;;
  ""|-h|--help)
    cat >&2 <<USAGE
Usage: $0 <alice|bob> <out.age> [age args...]

Defaults to passphrase mode. Extra args are forwarded to age, e.g.
   -r age1xxx          encrypt to a recipient (no passphrase prompt)
   -p --armor          passphrase + ASCII armor
   -R recipients.txt   one recipient per line

Restore:
   age -d <file>.age | tar -C ~/.anb/<side> -xf -
USAGE
    exit 2
    ;;
  *)
    echo "✗ side must be 'alice' or 'bob' (got $side)" >&2
    exit 2
    ;;
esac

[ -n "$out" ] || { echo "✗ missing <out.age> argument" >&2; exit 2; }
[ -d "$dir" ] || { echo "✗ $dir does not exist" >&2; exit 1; }
command -v age >/dev/null 2>&1 || { echo "✗ age CLI not on PATH (brew install age)" >&2; exit 1; }
shift 2

# Pick up only files that actually exist (some — exec-allowlist.json,
# authz.json — are optional and might not have been initialized).
present=""
for f in $files; do
  [ -f "$dir/$f" ] && present="$present $f"
done
[ -n "$present" ] || { echo "✗ nothing to back up in $dir" >&2; exit 1; }

# Default to passphrase mode if the caller passed no age args.
[ $# -eq 0 ] && set -- -p

# shellcheck disable=SC2086
tar -C "$dir" -cf - $present | age "$@" > "$out"
chmod 600 "$out"

count=$(echo $present | wc -w | tr -d ' ')
printf '✓ %s backup → %s (%s files, %s bytes)\n' "$side" "$out" "$count" "$(wc -c <"$out" | tr -d ' ')" >&2
