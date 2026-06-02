---
name: anb-secrets
description: Use when an AI agent needs to work with secrets kept in AnB / alice (the agent-vault successor) — running a command that needs an API token / DB password / kubeconfig, writing or rendering a config file that embeds secrets, auditing a file for leaked secrets, storing or rotating a secret, checking what exists, or auditing secret hygiene (weak / stale-KEK / missing-metadata entries). Keywords: alice, AnB, agent-vault, secret, vault, <agent-vault:key> placeholder, exec allowlist, mTLS KMS, ANB_BOB, alice audit, list -l, backfill-meta, secret strength, weak secret, KEK gen.
---

# AnB secrets (alice) for agents

## Core model — you never see plaintext

AnB splits secrets: ciphertext + metadata live with `alice` (the client you
call); the master key lives in `bob` (a KMS daemon over mTLS). You reference a
secret by name with `<agent-vault:KEY>` and `alice` resolves it only at the
moment of `exec`/`write`/`template`, into a child process or a file. The one
command that prints a raw value to your terminal (`get --reveal`) is gated to a
human TTY, so you can't casually dump plaintext.

## What you CAN run (no TTY needed — almost everything)

**Read / inspect (no writes):**
| Command | Use it to |
|---|---|
| `alice list [-l] [--json]` | See which secret names exist (no values). `-l` adds length / strength / KEK-gen columns; `--json` includes those fields too. |
| `alice has KEY... [--json]` | Check specific keys exist. |
| `alice get KEY` | Show a secret's **metadata** (no value): desc, set + last-updated time, KEK gen, exact length, strength estimate (`⚠ weak` flagged). |
| `alice audit [--strict]` | Local hygiene scan over stored metadata (no values): flags weak secrets, entries lagging the newest KEK gen, and entries missing metadata. `--strict` exits non-zero on any finding (CI). |
| `alice status` | Check bob is reachable + unlocked. |
| `alice read FILE` | Read a file with secrets masked to placeholders. |
| `alice scan FILE [--json]` | Audit a file for vaulted + suspected-unvaulted secrets (output is redacted — line numbers + key names, no values). |

**Use a secret (value goes into a process/file, never your stdout):**
| Command | Use it to |
|---|---|
| `alice exec [--env K='<agent-vault:KEY>']... -- CMD ARGS` | Run a command with secrets injected as env vars. Allowlist-gated (see below). |
| `alice write FILE [--content C]` | Restore `<agent-vault:KEY>` placeholders into a file (reads stdin if no `--content`). |
| `alice template SRC DST [--mode 0600] [--owner u:g]` | Render SRC's placeholders into DST with explicit mode/ownership (atomic; only decrypts the keys referenced). |

**Write the vault (authorized by Bob's per-identity authz):**
| Command | Use it to |
|---|---|
| `alice set KEY (--from-env V \| --stdin \| --generate) [--force]` | Store/rotate a secret. **Non-TTY requires a value source flag** (you can't be prompted). `--force` to overwrite. |
| `alice gen [--style apple\|full\|passphrase\|pin\|aes256] [-l N]` | Generate random password(s) to stdout (no vault access). |
| `alice import FILE --yes` | Bulk-import a `.env`. `--yes` required when non-interactive. |
| `alice init` | Initialize an empty vault. |
| `alice rm KEY --yes` | Remove a secret. `--yes` required when non-interactive. See caveat below. |
| `alice backfill-meta [--reason R]` | Populate length/strength/KEK-gen for secrets stored before those fields existed. Decrypts each entry only to **measure** it (value never printed); leaves set/updated times untouched; applies any lazy rewrap. Idempotent. Needs Bob + decrypt authz on every key. |

## What you CANNOT run (human-only, TTY required)

Only two:
- **`alice get --reveal`** — prints the raw value; gated to a human terminal. You
  almost never need it — use `exec`/`write`/`template` with the placeholder so
  the value flows into the process/file, not your context.
- **`alice shell`** — an interactive sub-shell with secrets injected; it has **no
  allowlist**, so it stays human-only. Use `alice exec` (allowlisted) instead.

## Recommended scenarios

1. **Run anything needing a secret** — `alice exec --env PGPASSWORD='<agent-vault:pg-prod>' -- /usr/bin/psql ...` (cmd must be an absolute path; allowlist-gated).
2. **Render/deploy a config** — `alice template app.tpl /etc/app/conf --mode 0640`, or `printf '...<agent-vault:KEY>...' | alice write ./conf`.
3. **Audit before committing** — `alice scan FILE` to catch leaked/hardcoded secrets; replace hits with `<agent-vault:KEY>` placeholders.
4. **Store / rotate** — `alice gen --style aes256 | alice set new-key --stdin --force`, or `alice set token --from-env CI_TOKEN`.
5. **Plan** — `alice list` + `alice status` before wiring anything.
6. **Audit hygiene** — `alice audit` to spot weak / stale-KEK / metadata-missing secrets; then `alice backfill-meta` for any missing metadata and `alice rekey` for stale-KEK entries. (Username-type entries flagged "weak" are usually fine — they aren't passwords.)

## Pattern: drive an external crypto tool with a vault-held key

A symmetric key can live in the vault and be injected via `alice exec` into any
CLI that reads its key from the environment — the tool encrypts/decrypts while
the key's plaintext never enters your context. Works for `encipherr`, an `age`
passphrase, `openssl`, `gpg --batch`, etc.

Example — **encipherr** (an AES CLI; its key stored once as `encipherr-key`):
```sh
EC=$(command -v encipherr)   # alice exec needs an ABSOLUTE path; this expands to one
alice exec --env ENCIPHERR_KEY='<agent-vault:encipherr-key>' -- "$EC" encrypt file data.txt -o data.enc
alice exec --env ENCIPHERR_KEY='<agent-vault:encipherr-key>' -- "$EC" decrypt file data.enc -o data.txt
```

- The operator blesses an allowlist rule for that absolute path once
  (default-deny); `--show-match-string` prints the exact pattern to add.
- Store the key once (human, or non-TTY via `--stdin`):
  `encipherr genkey | alice set encipherr-key --stdin`.
- The agent can now encrypt/decrypt files with a strong key it can never read —
  same guarantee as the rest of AnB, extended to a third-party tool.

## Important notes

- **`set` non-TTY needs a value source**: one of `--from-env`, `--stdin`, `--generate`. Without it (and no TTY) it errors — you can't be prompted for a value.
- **`rm`/`import` need `--yes`** when non-interactive (fail-closed otherwise).
- **`rm` has no server-side authz** — it deletes the local ciphertext entry and never contacts Bob, so Bob's per-identity authz can't gate it. Deletion is recoverable from an `anb-vault.sh` backup, but be deliberate: don't `rm --yes` keys you don't own.
- **Writes (`set`/`import`) ARE authorized by Bob** per-identity (the encrypt op checks which key prefixes your identity may write). An allowlist/authz error on `set` means your identity isn't authorized for that key — tell the human.
- **exec is default-deny**: the operator must pre-bless a regex rule in `~/.anb/alice/exec-allowlist.rules`. If `exec` is denied, stop retrying — tell the human the exact command + env keys you need (`--show-match-string` prints the pattern). cmd must be an absolute path.
- Never print a resolved secret to stdout/logs; keep it in the placeholder.

## Setup state (when nothing works)

If every command errors, alice may not be enrolled or bob may be down — run
`alice status`. Enrollment and `bob serve` are operator tasks; see the AnB README.
