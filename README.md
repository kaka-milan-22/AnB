# Alice and Bob

A client/server secrets vault for the age of AI agents. **Alice** (the client CLI
your agents call) keeps only ciphertext on disk and runs a redaction engine;
**Bob** (the daemon / KMS server) holds the master key and acts as an
encrypt/decrypt **oracle** over mutual TLS. The master key never lives on the
client and never touches disk in plaintext — it stays inside Bob.

It is the spiritual successor to [agent-vault](https://www.npmjs.com/package/@kaka-milan-22/agent-vault)
(TypeScript): the same command surface and redaction model, but key custody is
split out into a separate, authenticated service.

---

## Why

agent-vault stored its 256-bit AES master key in a plaintext file next to the
ciphertext, so any process running as the same user could read it and decrypt
everything. AnB removes the key from the client entirely:

- **Alice** stores AES-256-GCM ciphertext + metadata locally, runs redaction on
  `read`, restores placeholders on `write`, and asks Bob to encrypt/decrypt
  individual values over mTLS.
- **Bob** holds the master key (Argon2id-wrapped at rest, unlocked once by an
  operator, kept in `mlock`'d memory with an optional idle TTL) and serves
  crypto operations only to authenticated, authorized clients.

This is the envelope-encryption / KMS pattern (AWS KMS, HashiCorp Vault transit),
scoped down to a single self-hosted binary you fully control.

---

## Architecture

```
            mTLS (private CA, mutual cert verification, any network)
 ┌──────────────────┐   Alice sends ciphertext ─────►  ┌───────────────────────────┐
 │ alice (client)   │                                  │ bob (KMS daemon)          │
 │ • vault.json     │   ◄──── Bob returns plaintext     │ • master key (KEK)         │
 │   (AES-GCM)      │                                  │   mlock'd, idle TTL        │
 │ • redaction      │   Alice sends plaintext ──────►   │ • operator unlocks once    │
 │ • client cert/key│                                  │   with a master password   │
 │   (0600)         │   ◄──── Bob returns ciphertext    │ • private CA / authz /audit│
 └──────────────────┘                                  └───────────────────────────┘
```

The client cert's CommonName **is** the caller's identity. Bob authorizes every
request against it (like Kubernetes client-cert auth).

---

## Features

- **Full agent-vault command surface** — `read`, `write`, `has`, `list`, `set`,
  `get`, `rm`, `import`, `init`, `scan`.
- **Redaction engine** — `read` replaces known secret values and high-entropy
  unvaulted tokens with `<agent-vault:key>` / `<agent-vault:UNVAULTED:sha256:…>`
  placeholders; `write` restores them. Secret values never appear in `read`/`scan`
  output.
- **Agent-safe by default** — almost every command works without a TTY (`read`,
  `write`, `exec`, `template`, `scan`, `set`, `import`, `rm`, …). Only the two
  that expose a *raw value* (`get --reveal`) or an *un-gated injection shell*
  (`shell`) require an interactive terminal, so an agent — even under prompt
  injection — structurally can't dump plaintext to its terminal. Confidentiality
  beyond that is enforced by Bob's per-identity authz, not by the TTY split.
- **Agent-safe exec (operator-allowlisted)** — `alice exec --env KEY=<agent-vault:k> -- <cmd> <args>`
  is default-deny since v2.0.0. Operator pre-blesses exact
  Go RE2 regex rules in `~/.anb/alice/exec-allowlist.rules`.
  Matched invocations resolve placeholders into the child's env and
  `syscall.Exec` the child without further prompting (agent-autonomous);
  rules carry an optional env-subset column and label. Companion: `alice write --quiet`
  routes status lines to stderr.
- **Mutual TLS with a private CA** — no public CA, no ACME. Bob mints its own CA,
  server cert, and signs each client's CSR. Runs over any network (LAN, VPN,
  internet).
- **OOB enrollment pairing** — `bob sign-csr` shows the CSR identity, the
  public-key fingerprint, and a one-shot 8-digit pairing code; the Bob operator
  reads the code to Alice over a side channel. `alice install-cert` re-prompts
  for it and refuses the cert if it doesn't match. The code is bound to the
  issued cert's public key (commitment in a non-critical X.509 extension) and
  expires 10 minutes after sign-csr. `--no-pair` on both sides bypasses for
  scripted use.
- **Per-identity authorization** — map each identity to the key prefixes it may
  touch. Every request is audited.
- **Master key custody** — Argon2id-wrapped at rest, `mlock`'d in memory, core
  dumps disabled, `PR_SET_DUMPABLE=0` on Linux, zeroized on idle TTL or shutdown.

---

## Trust boundary (read this)

mTLS protects the **wire** and mutually authenticates both ends. It does **not**
protect the endpoints:

- Plaintext exists in Bob's memory (it decrypts) and in Alice's process (it
  receives results). A compromised Alice process gets the plaintext it asks for —
  unavoidable.
- **Alice's client private key is the new secret-zero.** Anyone who steals it can
  impersonate Alice to Bob. Keep it `0600`; revoke it (rotate the CA / reissue) if
  lost.
- **Bob is a centralized, high-value single point** — it holds the KEK and sees
  all plaintext that flows through it. Harden and audit it accordingly.
- **Enrollment pairing is a human OOB check, not a hard gate.** The 8-digit code
  defends against in-flight cert swaps and operator misclicks; it does *not*
  stop an attacker with filesystem access on Alice (who can copy `client.crt`
  past `install-cert` entirely) or on Bob (who can mint anything). 8 decimal
  digits ≈ 26.6 bits — enough for one-shot OOB inside a 10-minute window, not
  enough to lean on as a credential.
- **`alice exec` env values are same-uid visible.** Resolved plaintexts
  reach the child via env vars; same-uid processes can read them via
  `/proc/<pid>/environ` (Linux, 0o400 owner-only — i.e. same uid + root)
  or `ps eww` (macOS). This is strictly stronger than argv (Linux
  `/proc/<pid>/cmdline` is world-readable 0o644) but is NOT a
  memory-only channel. The allowlist limits *which* (cmd, args, env)
  triples can run, not what those processes do once running — the
  trust boundary is "alice + the operator-blessed binaries + same-uid
  process access". The TTY confirm-and-append flow added in v2.1
  gates on `isatty(stdin) && isatty(stderr)` — agents and pipes (the
  common case) never reach the prompt, so the allowlist cannot be
  widened from typical agent harnesses. An agent that explicitly
  allocates a pty (e.g. `expect`, `pty.spawn`, an agent driving
  tmux/screen) WOULD pass the gate and could send `yes\n`; if your
  agent runtime owns a pty, treat the prompt as "anyone with this
  TTY can widen the allowlist" and gate the binary itself, not just
  AnB.

---

## Install

Requires **Go 1.23+**.

```sh
# fastest: fetch the latest release straight onto your PATH
# Note the /v3/ in the path — Go modules require the major-version
# suffix for v2+. Tags v2.0.0 and v2.1.0 predate the /v2 module path
# and cannot be installed via `go install`; tags v2.2.0–v2.6.1 live
# under /v2/; v3.0.0+ lives under /v3/.
go install github.com/kaka-milan-22/AnB/v3/cmd/bob@v3.0.0
go install github.com/kaka-milan-22/AnB/v3/cmd/alice@v3.0.0

# …or build from a local clone of the v3.0.0 tag
git clone --branch v3.0.0 https://github.com/kaka-milan-22/AnB.git && cd AnB
go build -o bin/bob   ./cmd/bob
go build -o bin/alice ./cmd/alice
```

Replace `v3.0.0` with `@latest` to track unreleased changes on `main`.

After install, `alice version` / `bob version` (also `-V` / `--version`)
prints the build info — tag, commit, Go version, platform — read from the
binary's embedded `runtime/debug.BuildInfo`.

---

## Quick start

> **New here?** AnB lets your scripts and AI agents *use* secrets (API tokens,
> DB passwords, kubeconfigs) without ever seeing the plaintext. You reference a
> secret by name — `<agent-vault:KEY>` — and `alice` injects the real value into
> a command or file at the last moment. The master key never lives on the client;
> it stays inside a separate daemon (`bob`) you unlock once. Commands that *reveal*
> values require a human terminal, so an agent — even hijacked by prompt
> injection — structurally can't exfiltrate a secret.

### Local quick start (5 minutes)

Everything on one machine. (Multi-machine / over-a-network uses the out-of-band
pairing flow detailed below.)

```sh
# install both binaries (Go 1.23+)
go install github.com/kaka-milan-22/AnB/v3/cmd/bob@latest
go install github.com/kaka-milan-22/AnB/v3/cmd/alice@latest

# --- bob: private CA, wrapped master key, the mTLS daemon (operator, once) ---
bob ca init                           # → ~/.anb/bob/{ca.crt,ca.key}
bob init --host localhost             # prompts for a master password (or $ANB_BOB_PASSWORD)
bob serve -D --addr 127.0.0.1:8443    # prompts password, then detaches
                                      # stop later: kill $(cat ~/.anb/bob/bob.pid)

# --- alice: enroll on the same box ---
alice enroll --identity alice-local --bob localhost:8443 --ca ~/.anb/bob/ca.crt
#   → writes ~/.anb/alice/client.csr
bob sign-csr ~/.anb/alice/client.csr --out alice-local.crt --no-pair
#   → asks: Sign "alice-local" without pairing? [y/N]   — type y
alice install-cert ./alice-local.crt --no-pair
alice status                          # → Bob status: unlocked

# --- store a secret (interactive prompt; or non-TTY with --from-env/--stdin/--generate) ---
alice set stripe-key                  # prompts for the value
```

Then use it three ways — pick by *who* runs the command:

```sh
# (a) agent / script (no TTY): inject into a command — value is never printed.
#     The command must be an ABSOLUTE path, and an operator must first bless a
#     matching rule in ~/.anb/alice/exec-allowlist.rules (default-deny).
alice exec --env STRIPE_KEY='<agent-vault:stripe-key>' \
  -- /usr/bin/curl -sS -u "$STRIPE_KEY:" https://api.stripe.com/v1/charges

# (b) render a file: placeholders → real values, written atomically
printf 'token: <agent-vault:stripe-key>\n' | alice write ./config.yaml

# (c) human one-off: reveal the value (TTY required)
alice get stripe-key --reveal
```

**For AI agents:** install the bundled skill at `skills/anb-secrets/` into your
agent (`~/.claude/skills/` or a project's `.claude/skills/`). It teaches the
agent to use `list`/`read`/`write`/`exec` with `<agent-vault:KEY>` placeholders
instead of trying to read plaintext — the full non-TTY command surface.

---

### Full setup (multi-machine, with out-of-band pairing)

### 1. Set up Bob (operator, once)

```sh
# create the private CA (trust root for everyone)
bob ca init

# generate + wrap the master key, mint the server cert.
# --host lists the SANs Alice will verify (add your real hostname/IP for remote use)
bob init --host bob.internal,10.0.0.5
#   → prompts for a master password (or set $ANB_BOB_PASSWORD)

# run the oracle (foreground)
bob serve --addr :8443
#   → prompts for the master password, then listens on mTLS

# …or daemonize: prompt for the password on the TTY, then detach into the background
bob serve -D --addr :8443
#   → ✓ bob daemonized (pid N) → ~/.anb/bob/bob.log
#     stop with: kill $(cat ~/.anb/bob/bob.pid)   (SIGTERM zeroizes the key)
```

`-D` reads the master password interactively, validates it, then re-execs a
detached child and hands it the password over a pipe — so the key material never
lands in the environment or on disk. `--log` overrides the log path.

State lives in `~/.anb/bob/` (override with `--dir` or `$ANB_BOB_DIR`):
`ca.crt ca.key server.crt server.key envelope.json authz.json` (plus
`bob.log` / `bob.pid` when run with `-D`).

**Configure authorization before serving in production.** `bob init` writes an
`authz.json.example` next to the other state files; copy it to `authz.json` and
edit the `rules` block so each Alice identity gets only the key prefixes it
needs. Without `authz.json`, Bob runs ALLOW-ALL (every authenticated client
sees every key) and logs a warning at startup. See [Authorization](#authorization-authzjson-in-bobs-dir)
below for the schema.

Hand `ca.crt` to each Alice out of band (it's the public trust anchor).

### 2. Enroll Alice (with operator pairing)

`bob sign-csr` and `alice install-cert` exchange a one-shot 8-digit pairing
code out-of-band: Bob shows it to its operator at sign time, the operator
reads it to Alice's operator over a separate channel (voice / Signal / QR),
and Alice types it back at install time. The code is bound to the issued
cert's public key, so an in-flight cert swap detunes it; it expires 10 minutes
after sign-csr.

```sh
# 1) on Alice's machine — generate keypair + CSR, install the CA, save profile
alice enroll \
  --identity alice-laptop \
  --bob bob.internal:8443 \
  --server-name bob.internal \
  --ca ./ca.crt
#   → writes client.key (0600), client.csr, ca.crt, config.json

# 2) send client.csr to the Bob operator; Bob reviews + signs interactively
bob sign-csr alice-laptop.csr --out alice-laptop.crt
#   CSR identity:  alice-laptop
#   CSR pubkey fp: 5f8a…c1   (sha256 of SubjectPublicKeyInfo)
#   Pairing code:  47281930  (show to Alice OOB; expires in 10m at 14:23 UTC)
#   Sign? [y/N]: y
#   ✓ wrote alice-laptop.crt

# 3) Bob operator transmits 47281930 to Alice operator via a side channel

# 4) on Alice's machine — install the signed cert and verify the code
alice install-cert ./alice-laptop.crt
#   Cert identity:  alice-laptop
#   Cert pubkey fp: 5f8a…c1
#   Enter the 8-digit pairing code: 47281930
#   ✓ pairing verified — installed client cert

# 5) verify the whole chain end-to-end
alice status
#   Identity:   alice-laptop
#   Bob:        bob.internal:8443 (server-name bob.internal)
#   Bob status: unlocked
```

**Wire format.** The cert carries one non-critical X.509 extension under a
project OID in the `2.25.…` arc (concrete UUID-derived value chosen in
source). Its value is ASN.1 `SEQUENCE { commit OCTET STRING (SIZE(32)),
expiresAt GeneralizedTime }`, where `commit = SHA-256(code ‖ pubkey_fp)`,
`code` is the 8 ASCII digits Bob displayed, and `pubkey_fp` is the SHA-256 of
the cert's `SubjectPublicKeyInfo` DER. Cert distribution stays a single file
and Bob's signature covers `expiresAt`, so the deadline can't be extended
after issuance.

**Automation escape hatch.** When Alice and Bob are both scripted (CI,
bring-up of many clients) and no OOB channel exists, pass `--no-pair` to
**both** `bob sign-csr` and `alice install-cert`. Bob will WARN on each
unpaired sign-out and the trust model degrades to "anyone with shell on Bob
can mint Alices". To keep Bob interactive but skip Alice's prompt (you already
relayed the code into the environment), set `ANB_PAIR_CODE=47281930` before
`alice install-cert`.

### 3. Daily use

```sh
# store a secret (interactive, human only — encrypted by Bob, ciphertext stored locally)
alice set stripe-key
alice set db-url --from-env DATABASE_URL

# list / inspect
alice list                       # list all stored keys
alice get stripe-key             # metadata only
alice get stripe-key --reveal    # shows the value (TTY required)

# `alice get <key>` (no --reveal) prints metadata, never the value:
#   Key:      stripe-key
#   Desc:     prod payments
#   Set at:   2026-06-02T13:25:19Z   # first stored
#   Updated:  2026-06-02T18:40:02Z   # last value change (omitted if same as Set at)
#   KEK gen:  2                      # KEK generation wrapping this entry
#   Length:   20 bytes               # exact plaintext length
#   Strength: ~128 bit (excellent)   # charset-estimated, 8-bit-quantized
# Length is exact — the GCM ciphertext already implies it, so there's nothing
# to hide. Strength is kept coarse (charset composition is NOT recoverable from
# the ciphertext). `alice list --json` also reports each entry's keyEpoch, so
# you can spot entries lagging the current KEK.
#
# Secrets stored before these fields existed show only Key/Set at. To populate
# them in one pass (Bob decrypts each entry to MEASURE it; values are never
# printed; createdAt/updatedAt are untouched):
#   alice backfill-meta

# Three ways to deliver a vault secret to a process. Pick by *who* runs the
# command — see "Choosing between alice exec, alice shell, and alice get"
# below. NOTE: single-quote --env values so the shell doesn't expand `<` / `>`.

# (a) Agent / script / non-TTY — gated by exec-allowlist.rules
#     (v3.0+ regex-per-line; first call prompts on TTY, hard-deny otherwise)
alice exec --env 'GH_TOKEN=<agent-vault:gh-pat>' \
  -- /opt/homebrew/bin/gh api user

# (b) Operator running multiple commands — alice shell injects env once
#     for the session. TTY-only, no allowlist. The cleaner answer for
#     interactive batches (e.g. encrypting a folder of files).
alice shell --env 'GH_TOKEN=<agent-vault:gh-pat>'
$ gh api user
$ gh issue list --repo foo/bar
$ exit

# (c) Operator one-off — pipe or inline expansion, no sub-shell.
GH_TOKEN=$(alice get gh-pat --reveal) gh api user

# agents use the safe commands — secrets stay redacted
alice read config.yaml           # secret values → <agent-vault:key>
echo 'token: <agent-vault:stripe-key>' | alice write config.yaml

# audit a file for vaulted + unvaulted secrets
alice scan config.yaml

# bulk import a .env, remove
alice import .env
alice rm old-key
```

---

## Migrating from agent-vault

With Bob serving, `scripts/migrate-from-agent-vault.sh` moves your existing
secrets across:

```sh
scripts/migrate-from-agent-vault.sh --dry-run   # show the plan, change nothing
scripts/migrate-from-agent-vault.sh             # migrate
```

It bulk-imports all keys (restores `<agent-vault:key>` placeholders into a
temp file, runs `alice import --min-length 1`, then `rm -P`s it). Key
names are preserved, so existing `<agent-vault:key>` placeholders keep resolving.
It migrates only — it never uninstalls or deletes agent-vault. (A direct
`agent-vault get --reveal | alice set --stdin` pipe can't work: both tools refuse
when stdout isn't a TTY, which is why the script routes through a temp file.)

---

## Command reference

### bob (operator)

| Command | Description |
|---|---|
| `bob ca init [--cn N] [--ttl-years N] [--force]` | Create the private CA |
| `bob init [--host h1,h2] [--force]` | Generate + wrap the master key, mint the server cert |
| `bob sign-csr <csr> [--out F] [--ttl-days N] [--no-pair]` | Sign an Alice CSR → client cert. Interactive by default: prints CSR identity + pubkey fingerprint + an 8-digit OOB pairing code (10-minute TTL), confirms y/N before signing. `--no-pair` skips pairing and warns. |
| `bob serve [--addr :8443] [--ttl SECONDS] [-D] [--log FILE]` | Unlock + run the mTLS oracle (`-D` detaches into the background) |
| `bob rotate-master-password [--keep-key]` | New password + a fresh K version (lazy rewrap); `--keep-key` retains the v2.3 behavior (password only, no new K). See "Master key rotation" below. |
| `bob rotate-master-key [--finalize <id>] [--yes]` | Add a fresh K under the same password; `--finalize <id>` retires an old K (after every alice has rekey'd off it). |
| `bob list-keys` | Show K versions in `envelope.json` (no password needed). |

### alice — agent-safe (no TTY required)

Almost the entire surface. A value never reaches your terminal — it flows into a
child process (`exec`), a file (`write`/`template`), or stays as metadata.

| Command | Description |
|---|---|
| `alice read <file>` | Print the file with secrets redacted |
| `alice write <file> [--content C] [--quiet]` | Restore `<agent-vault:…>` placeholders (stdin if no `--content`) |
| `alice has <keys...> [--json]` | Check existence (local metadata) |
| `alice list [--json]` | List all stored key names |
| `alice status` | Enrollment + Bob reachability/unlock state |
| `alice scan <file> [--json]` | Audit a file for vaulted + unvaulted secrets (redacted output — line numbers + key names, no values) |
| `alice get <key>` | Secret **metadata** (no value). The value needs `--reveal` — TTY only, see below. |
| `alice exec [--env KEY=V]... [--reason R] [--show-match-string] -- <cmd> [args...]` | Match `~/.anb/alice/exec-allowlist.rules` (Go RE2); on hit, resolve placeholders and `syscall.Exec` the child. Default-deny; cmd must be an absolute path. `--show-match-string` prints the canonical match string. |
| `alice template <src> <dst> [--mode 0600] [--owner u:g] [--reason R]` | Render `<src>`'s placeholders into `<dst>` (atomic; explicit mode/owner; decrypts only referenced keys). See "Templating". |
| `alice set <key> (--from-env V \| --stdin \| --generate) [--desc D] [--style S] [-l N] [--force]` | Store/rotate a secret (encrypted by Bob). **Non-TTY needs a value source**; `--force` to overwrite. Authorized by Bob's per-identity authz. |
| `alice gen [--style S] [-l N] [-n N]` | Generate & print random password(s) — see below |
| `alice import <file> --yes [--min-length N]` | Bulk-import a `.env` (`--yes` required when non-interactive) |
| `alice init` | Initialize an empty local vault |
| `alice rm <key> --yes` | Remove a secret (`--yes` when non-interactive). **Local delete, no server-side authz** — recover from an `anb-vault.sh` backup. |

### alice — human-only (TTY required)

Only the two commands that expose a raw value or an un-gated injection shell:

| Command | Description |
|---|---|
| `alice get <key> --reveal [--reason R]` | Print the secret **value** — gated to a TTY (can't pipe/redirect). `--reason` logged in Bob's ALLOW line. |
| `alice shell [--env K=V]... [--reason R] [-- shell args...]` | Interactive sub-shell with `--env` injected; **no allowlist**, so TTY-only; sets `ALICE_SHELL=1`. See "Sub-shell". |

### alice — migration

| Command | Description |
|---|---|
| `alice rekey-status` | Per-K-version entry counts in vault.json (local; no Bob round-trip) |
| `alice rekey [--reason R]` | Force-migrate every vault entry to Bob's current K version |

### alice — setup

| Command | Description |
|---|---|
| `alice enroll --identity N --bob HOST:PORT --ca ca.crt [--server-name SAN]` | Generate keypair + CSR, install CA, save profile |
| `alice install-cert <client.crt> [--no-pair]` | Verify the 10-minute OOB pairing code embedded in the cert, then install it. `--no-pair` accepts certs signed without pairing. Code may also come from `$ANB_PAIR_CODE` instead of the prompt. |

Flags may appear before or after positional arguments.

---

## Generating passwords

`alice gen` prints fresh random passwords (stdout must be a TTY, so it can't be
piped or captured); `alice set <key> --generate` generates one and stores it
**without ever printing it**. Both take `--style` and `-l`; `gen` also takes `-n`.

| `--style`    | `-l` controls     | default | range |
|--------------|-------------------|--------:|-------|
| `apple`      | groups of 6 chars |       3 | 1–8   |
| `full`       | total characters  |      20 | 8–100 |
| `passphrase` | words             |       5 | 3–12  |
| `pin`        | digits            |       6 | 4–32  |

`-n` (gen only) prints that many candidates (1–10, default 1).

```sh
alice gen                            # apple style, 3 groups → Hub3vx-mzg5fc-9kqpw2
alice gen --style full -l 32 -n 3    # three 32-char passwords with symbols
alice gen --style passphrase -l 6    # tidy-Cobra-mellow-quartz-vivid-half-09
alice set stripe-key --generate --style full -l 24   # generate + store, never printed
```

- **`apple`** — Apple-style hyphenated alphanumeric, guaranteed lower/upper/digit.
- **`full`** — adds shell-safe symbols (`!#$%&*+-=?@^_~`), guaranteed all four classes.
- **`passphrase`** — EFF large wordlist, one word capitalized + a trailing number.
- **`pin`** — digits only.

All randomness comes from `crypto/rand`.

---

## Backup & restore

`scripts/anb-vault.sh` is the full backup/restore tool for both sides' state.
It packs the *entire* state directory (minus volatile `*.log`/`*.pid`/`*.sock`/
`*.lock`), embeds a SHA-256 `MANIFEST.txt` for content-integrity, encrypts with
[age](https://filippo.io/age), keeps timestamped versions, and restores
atomically — always snapshotting the current config first. For `bob` it also
stops the daemon before swapping state, restarts it, and confirms the
round-trip with `alice status`.

```
anb-vault.sh backup  <alice|bob|both> [-o DIR] [-r RECIP | -R FILE | -p] [-k N] [--armor]
anb-vault.sh restore <alice|bob>  <file.age> [-d STATE_DIR] [-i IDENTITY] [--addr H:P] [--no-restart] [--force]
anb-vault.sh verify  <file.age> [-i IDENTITY]
anb-vault.sh list    [-o DIR]
```

### Encryption: prefer an age recipient

The CA / mTLS private keys (`ca.key`, `server.key`, `client.key`) live as
**plaintext at rest** (0600), so the age layer is their *only* protection in a
backup. Treat the backup's age key like the CA key itself.

- **Recipient mode (recommended)** — `-r age1...` / `-R file` /
  `$ANB_AGE_RECIPIENT`. Only the **public** key is needed to back up, so it can
  sit in cron/env with no secret online; the **private** identity (needed only
  to restore) stays offline. No weak-passphrase risk.
- **Passphrase mode** — `-p` (TTY only). Simple, but security rides entirely on
  the passphrase.
- **Fail-closed** — with no recipient and no TTY (e.g. a misconfigured cron),
  the tool *refuses* rather than silently falling back to weak/no encryption.

```sh
# generate a backup keypair once; keep the identity file offline
age-keygen -o ~/anb-age-key.txt          # prints "Public key: age1..."

export ANB_AGE_RECIPIENT=age1...         # public key — safe in env/cron
anb-vault.sh backup both                 # → ~/anb-backups/anb-{alice,bob}-<UTC>.age, keeps newest 10
anb-vault.sh backup bob -k 30            # bob only, keep 30
anb-vault.sh list
anb-vault.sh verify ~/anb-backups/anb-bob-<ts>.age -i ~/anb-age-key.txt
```

Output goes to `${ANB_BACKUP_DIR:-~/anb-backups}` (mode 700), files are 0600,
named `anb-<side>-<UTCtimestamp>.age`. Retention (`-k`, default 10) prunes only
regular backups per side; `prerestore` snapshots are never auto-pruned.

### Restore is safe by construction

1. The incoming archive is **verified first** (decrypt + manifest). A bad
   archive aborts with your live config untouched.
2. The current state is **snapshotted** to a `prerestore` age archive.
3. The swap is **atomic**: old dir → `<dir>.bak-<ts>`, new state moved in,
   `*.key` re-chmod'd to 0600. The tool prints a one-line rollback command.

```sh
export ANB_AGE_IDENTITY=~/anb-age-key.txt        # private key, to decrypt
export ANB_BOB_PASSWORD=...                       # optional; else prompted on TTY at restart

# bob: verify → snapshot current → stop daemon → swap → restart → alice status
anb-vault.sh restore bob ~/anb-backups/anb-bob-<ts>.age

# dry-run a restore into a temp dir without touching the live env or daemon:
anb-vault.sh restore bob ~/anb-backups/anb-bob-<ts>.age -d /tmp/rt/bob --no-restart
```

`--addr` (default `127.0.0.1:8443`, or `$ANB_BOB_ADDR`) is the address used to
restart bob; `--no-restart` skips the restart + status check; `--force` skips
the interactive confirm.

> Restoring `bob` writes plaintext private keys to `<dir>.bak-<ts>`. Once you've
> confirmed `alice status` reports `unlocked`, delete those `.bak` dirs so
> plaintext key copies don't linger.

### Sibling: dotfiles backup

`scripts/dotfiles-backup.sh` applies the same age-tarball model to your
dotfiles + Claude skills: `scan` flags secret-format content / key files before
packing, `backup` does tar (junk excluded) → age-encrypt → 0600 with retention
and optional `rclone --upload`, `restore` decrypts to a fresh dir (never
clobbers `$HOME`). Unlike a dotfiles *manager* (chezmoi et al.) it produces one
encrypted blob — ciphertext at rest wherever you store it. Run
`scripts/dotfiles-backup.sh -h`.

---

## Master key rotation (v2.6+)

Since v2.6 Bob stores the master key as a **versioned set** (`envelope.json`
schema v3) and `bob rotate-master-password` **also adds a fresh K version by
default**. Old vault.json ciphertext still decrypts (Bob can open any version
it holds); on the next alice access of an old-K entry, Bob also returns the
same plaintext re-sealed under the current K — alice writes it back to
vault.json transparently. This is the "lazy rewrap" model from AWS KMS /
Vault Transit, scoped down to a single self-hosted binary.

### Three knobs

| Command | Effect |
|---|---|
| `bob rotate-master-password` | New password + new K (default). Bumps `current`. Old K versions are re-wrapped under the new password and stay around until you `--finalize` them. |
| `bob rotate-master-password --keep-key` | v2.3 behavior — just change the password; no new K. |
| `bob rotate-master-key` | New K under the SAME password (no password change). Useful for hygiene rotation between password changes. |
| `bob rotate-master-key --finalize <id>` | Retire K_<id>. Refuses to retire `current`. After this, ciphertext under K_<id> is permanently unreadable. |
| `bob list-keys` | List K versions + creation time + KDF params + which is current. No password needed. |
| `alice rekey-status` | Local count of vault.json entries by K version (run on every enrolled alice before `--finalize`). |
| `alice rekey` | Force-migrate every vault.json entry to the current K (otherwise it happens lazily on access). |

### Lazy vs. eager migration

- **Lazy** (default): alice reads `get`/`read`/`exec`/`template`/`shell` decrypt
  old-K entries on demand; Bob's response carries a `rewrappedPacked` field
  with the same plaintext under the current K, which alice writes back to
  `vault.json`. Over time the vault drifts to the current K with zero operator
  effort. Operator visibility via `alice rekey-status`.
- **Eager**: `alice rekey` decrypts every stored entry via `DecryptMany` and
  writes back all rewrapped values in a single `vault.json` `Save`. Used right
  before `--finalize` to confirm zero non-current entries.

### When to `--finalize`

Old K versions stay in `envelope.json` (re-wrapped under the current
password) until you explicitly retire them. There's no rush — they're
encrypted at rest. But two reasons to clean up:

1. **Hygiene** — every K version on disk is one more KDF target if an
   attacker steals `envelope.json` + the master password.
2. **Suspected leak** — if you think K_<id> was exposed (e.g. an attacker
   briefly had filesystem + memory access), `--finalize` removes Bob's
   ability to decrypt under that K. Attackers who already extracted the
   K bytes can still decrypt offline; what `--finalize` defends is Bob
   being used as a decrypt oracle going forward, plus any future
   `envelope.json` leak no longer containing K_<id>.

Routine workflow:

```sh
scripts/anb-vault.sh backup bob                       # 0. recovery snapshot (see Backup & restore)

bob rotate-master-password                            # 1. new pw + new K (default)
# ... or: bob rotate-master-key                       #    new K only, no pw change

bob list-keys                                         # 2. see what's there
alice rekey-status                                    # 3. see what's still on old K (per alice)
alice rekey                                           # 4. force-migrate this alice
# repeat on every enrolled alice if you have more than one identity

bob rotate-master-key --finalize 1                    # 5. retire K_1 (NOT current)
# Restart the daemon so K_1 is also wiped from in-memory:
kill $(cat ~/.anb/bob/bob.pid) && bob serve -D --addr 127.0.0.1:8443
```

### Inputs (same env-var convention as the rest of bob)

| Field | Env var (for automation) | Interactive default |
|---|---|---|
| Current password (rotate-pw, rotate-key, --finalize) | `$ANB_BOB_PASSWORD` | `Current master password:` / `Master password:` |
| New password (rotate-master-password only) | `$ANB_BOB_NEW_PASSWORD` | `New master password:` (entered twice) |
| Bypass `--finalize` confirm | `--yes` flag | interactive `Type 'yes' to confirm:` |

### Atomic failure modes

Every rotation/finalize is atomic at the disk level: if any unwrap fails
(wrong password, malformed envelope, bad K_id), `envelope.json` is
byte-for-byte unchanged.

### Bonus: free KDF cost refresh

Every wrapped K carries its own Argon2id salt + params (`m`, `t`, `p`).
Every rotation re-randomizes the salt and picks up the current
`crypto.DefaultParams()`, so if the project ever bumps the KDF cost
the next rotation transparently upgrades the new K to it. Old K versions
keep their original params — useful as historical record but also another
reason to `--finalize` eventually.

---

## Audit clarity (`--reason`, allowlist `label`)

Bob's audit log (whatever sink it points at — stderr in the foreground, the
`-D` log file in daemon mode) records every authorized access. Two v2.4 fields
make that log answer **why**, not just *who/when/what*:

- **`alice get <key> --reveal --reason "<why>"`** and
  **`alice exec --reason "<why>" -- …`** add a free-text reason that Bob logs
  in the ALLOW line as `reason="..."`.
- **Allowlist entries may carry `"label": "<short-name>"`** —
  purely operator metadata (it doesn't participate in matching). When a
  labeled entry runs without an explicit `--reason`, alice automatically uses
  `[<label>]` as the audit reason, so blessed agent paths get free attribution.

```sh
alice get reminder-bot-token --reveal --reason "rotating reminder bot creds"

# allowlist entry with "label": "n9e-login":
alice exec --env N9E_USER='<agent-vault:n9euser>' \
           --env N9E_PASSWORD='<agent-vault:n9epassword>' \
           -- /Users/.../node /Users/.../n9e-auth.js
```

**Important: `--reason` is audit-only, not an authorization input.** A
compromised agent can forge any reason it wants. The value is for the
*operator* reading the log: anomalous reasons (or expected ones missing) are
the signal. AnB never gates access on reason content.

See "Audit log format" below for the JSON shape these calls produce in
`bob.log`.

---

## Audit log format (v2.5+, JSON one-event-per-line, **breaking from v2.4**)

Every bob log line is a self-contained JSON object — no `audit ` prefix, no
`log.LstdFlags` timestamp prefix, the timestamp lives **inside** the payload
as RFC3339Nano `ts`. Designed for Loki / n9e blackbox / Grafana / jq.

Pre-v2.5 consumers that grepped `ALLOW`/`DENY` lines need to switch to JSON
parsing; this is the v2.5 breaking change.

### Event kinds

| `kind` | Fields |
|---|---|
| `ALLOW` | `identity`, `op`, `keys` (array), `reason` (operator-supplied, omitted when empty) |
| `DENY` | `identity`, `op`, `key`, `cause` (e.g. `"unauthorized"`) |
| `RATELIMIT` | `identity`, `op`, `cause: "limit-exceeded"` |
| `KEY_REWRAP` | `identity`, `op`, `key` (or `keys` for `decryptMany`), `count` — lazy K migration happened (v2.6+) |
| `HANDSHAKE_FAIL` | `remote`, `err` |
| `DROP` | `identity`, `cause` (e.g. `"request-too-large"`) |
| `PANIC` | `err`, `stack` |
| `SERVING` | `addr`, `dir` |
| `SHUTDOWN` | — |
| `AUTOLOCK` | `msg` |
| `WARN_ALLOW_ALL` | `msg` |

### `jq` cookbook

```sh
LOG=~/.anb/bob/bob.log

# the most recent ALLOW with a reason
jq -c 'select(.kind=="ALLOW" and .reason)' "$LOG" | tail -1

# top 10 identities by decrypt count today
jq -c 'select(.kind=="ALLOW" and (.op|test("^decrypt"))) | .identity' "$LOG" |
  sort | uniq -c | sort -rn | head

# rate-limit events in the last hour
jq -c --argjson cutoff "$(date -u -v-1H +%s)" \
  'select(.kind=="RATELIMIT") | select((.ts | fromdate) > $cutoff)' "$LOG"

# anything that mentions a specific vault key
jq -c 'select((.keys // [.key] // []) | index("stripe-key"))' "$LOG"
```

---

## Rate limiting (v2.5+)

Bob caps each identity's decrypt-class requests (`decrypt` + `decryptMany`).
Default is **100 ops/minute** (built-in); operators can override per identity
in `authz.json`. Encrypt and Status are not limited (`encrypt` is operator-TTY
driven via `alice set`; `status` is cheap).

```json
{
  "rules":       { "alice-laptop": ["*"], "agent-ci": ["ci-"] },
  "rate_limits": {
    "default":      100,
    "alice-laptop": 500,
    "agent-ci":     20
  }
}
```

Resolution: `rate_limits[<identity>]` > `rate_limits.default` > built-in `100`.
A bucket starts full and refills at `cap/60` tokens/second. Exhausting the
bucket returns a `rate-limit` response code and emits a `RATELIMIT` audit
event; bucket state lives in memory and resets on bob restart.

Use this to bound the blast radius of a runaway agent without taking the
service down. For interactive operators, 100/min is generous; CI / agent
identities are good candidates for tighter caps.

---

## Templating (`alice template`)

`alice template <src> <dst> [--mode 0600] [--owner u:g] [--reason R]` renders a
source file's `<agent-vault:k>` placeholders into a destination file with
explicit permissions. Atomic write (tmp + rename), default mode `0600`. The
deploy-style sibling of `alice write` (which is stdin-driven).

```sh
cat > /tmp/myapp.tpl <<'EOF'
DB_URL=postgres://app:<agent-vault:db-password>@host/myapp
API_TOKEN=<agent-vault:api-token>
EOF

alice template /tmp/myapp.tpl /etc/myapp/env --mode 0640 --owner myapp:myapp \
  --reason "deploy myapp"
# ✓ Rendered /tmp/myapp.tpl → /etc/myapp/env (2 placeholders restored, mode 0640)
```

`--owner` typically requires root. Human-only (TTY required) — writes
plaintext secrets to disk.

---

## Sub-shell (`alice shell`)

`alice shell [--env K=V]... [--reason R] [-- shell-cmd args...]` spawns an
interactive sub-shell with `--env` values (placeholder-restored) injected,
plus `ALICE_SHELL=1` so your rc files can change PS1 to mark the session.
TTY-only (stdin + stderr must both be terminals); no allowlist gate.

```sh
alice shell --env GH_TOKEN='<agent-vault:gh-pat>'
# → shell /bin/zsh with env=[GH_TOKEN] (set ALICE_SHELL=1)
$ echo $ALICE_SHELL
1
$ gh api user
…
```

Why no allowlist (unlike `alice exec`)? The TTY gate already excludes agents
structurally — they can't fake a TTY pair — so the allowlist would only add
friction for the operator who is, by virtue of being at the keyboard, the
authorization. Audit reason defaults to `[shell]` when `--reason` isn't given.

---

## Choosing between `alice exec`, `alice shell`, and `alice get`

AnB gives you three ways to deliver a vault secret to a process. They look
similar from the outside; they differ in **who can use them** and **what review
gate they pass through**. Picking the wrong one creates either security gaps
(no review) or operator pain (review on every iteration).

| Path | Who | Review gate | When to reach for it |
|---|---|---|---|
| **`alice exec --env KEY=<agent-vault:k> -- cmd args...`** | Agent **or** operator; non-TTY OK | **Allowlist** — Go RE2 regex per line in `exec-allowlist.rules`; first-miss prompts on TTY, hard-denies otherwise | Scripts, agents, CI, cron — anything that runs without a human at the keyboard. The allowlist is the only thing reviewing argv when no human is. |
| **`alice shell --env KEY=<agent-vault:k>`** | Operator only (TTY required on stdin + stderr) | **TTY gate** — agents can't fake it | Interactive batch work: encrypting a folder of files, running 50 `kubectl` calls with a token, an afternoon of `gh` API exploration. One bless, many commands, env evaporates on `exit`. |
| **`alice get <name> --reveal`** piped to a tool | Operator only (TTY required) | **TTY gate** | One-off command that reads its key from stdin or a single positional arg. Or `KEY=$(alice get name --reveal) cmd …` for one-line env injection without spawning a sub-shell. |

### Why the allowlist isn't a universal answer

`alice exec`'s strict per-invocation matching is **deliberately inconvenient
for repeated operator work**. It's calibrated for the threat model where an
agent under prompt-injection crafts a malicious invocation — there, every
review pass matters. For an operator at the keyboard running the same shape
of command 50 times in a row, that calibration is wrong: the operator audits
the command shape once (mentally), and asking them to type `yes` 50 times
trains them into reflex-yes. Reach for `alice shell` instead — bless the env
injection once for the session, then iterate freely.

### Concrete examples

```sh
# Batch encryption with encipherr — operator iterating over many files.
# Wrong: alice exec each time (allowlist prompts per file or needs a strict entry per file).
# Right: alice shell once, then unlimited encipherr invocations in the session.
alice shell --env 'ENCIPHERR_KEY=<agent-vault:encipherr-key>'
$ encipherr encrypt file ~/photos/2026-05.tar
$ encipherr encrypt file ~/docs/q2-report.pdf
$ encipherr decrypt file ~/backup/old.enc
$ exit
```

```sh
# One-off operator command — pipe directly, no sub-shell needed.
ENCIPHERR_KEY=$(alice get encipherr-key --reveal) encipherr encrypt file foo.txt
```

```sh
# Agent-driven workflow (cron, CI, Claude Code Bash tool, etc.) — alice exec
# with allowlist. Non-TTY callers structurally can't reach the prompt.
alice exec --env 'GH_TOKEN=<agent-vault:gh-pat>' \
  -- /opt/homebrew/bin/gh api user
# First call: deny + TTY prompt (if you happen to be at one). After yes,
# /Users/you/.anb/alice/exec-allowlist.rules holds a literal-regex entry and
# the agent path runs without further interaction.
```

### A pitfall to avoid

Don't pipe `yes |` into `alice exec` to clear allowlist prompts in bulk —
that's the reflex-yes failure mode, and it bypasses the protection allowlists
exist to provide. If you're doing enough iteration to be tempted, the right
move is to drop out of `alice exec` and use `alice shell` instead. The TTY
gate is doing the actual security work; the allowlist is the agent-specific
half of the same gate.

---

## Allowlist rules format

`alice exec` consults `~/.anb/alice/exec-allowlist.rules` to decide
whether to inject vault secrets into a given child invocation.

The file is plain text. Each non-empty, non-comment line is one rule:

    <regex>	<env-csv>	#<label>

Three tab-separated fields. The last two are optional. Implicit
`^…$` anchor on the regex (operator cannot disable).

**How matching works:**

1. alice canonicalises the invocation as `shellescape(cmd) + ' ' +
   shellescape(arg1) + ' ' + …`. Args with safe characters
   (`[A-Za-z0-9_\-./:=@,]`) pass through unchanged; anything else
   is POSIX single-quote wrapped.
2. Rules are scanned top to bottom; first match wins.
3. A match requires both the regex test to pass AND the operator's
   `--env` keys to be a subset of the rule's env-csv.
4. No match → hard-deny (TTY callers see an auto-bless prompt; non-
   TTY callers exit non-zero with the suggested rule line).

**Env-csv column:**

| Value | Meaning |
|---|---|
| empty | `--env` flags not allowed for this rule |
| `KEY1` | operator's `--env` keys ⊆ `{KEY1}` |
| `KEY1,KEY2,KEY3` | operator's `--env` keys ⊆ `{KEY1, KEY2, KEY3}` |
| `*` | any `--env` name allowed (rare; loud warning) |

**Authoring rules:**

`alice exec --show-match-string -- /path/to/cmd args...` prints the
exact canonical string your regex must match. Build your regex from
that string with `^…$`-bounded patterns.

**Example file:**

```text
# encipherr file ops with any path
^/Users/me/\.local/bin/encipherr (encrypt|decrypt) file '?[^']+'?$	ENCIPHERR_KEY	# encipherr file ops

# gh issue/api read-only with token
^/opt/homebrew/bin/gh (api .+|issue view [0-9]+)$	GH_TOKEN	# gh ro

# bob list-keys, no env
^/Users/me/go/bin/bob list-keys$		# bob list-keys

# n9e login with two env vars (either or both allowed)
^/usr/bin/node /Users/me/work/n9e-login\.js$	N9E_USERNAME,N9E_PASSWORD	# n9e login
```

**Auto-bless:**

When `alice exec`'s invocation doesn't match any rule AND both stdin
and stderr are TTYs, alice prompts:

    Append this entry to exec-allowlist.rules? Type 'yes' to confirm [y/N]:

On `yes`, alice appends a fully-escaped literal regex (so it matches
exactly the originating invocation, no wildcards). Operator widens
by hand-editing later. On anything else, alice exits non-zero
silently — the deny output it already printed once is enough.

**Migration from v2.x:** On first run of v3.0+ alice, an existing
`exec-allowlist.json` is converted to `exec-allowlist.rules`
in place; the original is renamed `exec-allowlist.json.bak`. The
generated rules match exactly the same invocations the JSON entries
did — strictly behaviour-preserving.

### Linting your allowlist

`alice allowlist-check` (v3.1+) runs heuristic checks over your rules
file and reports operator footguns:

```text
$ alice allowlist-check
Checking /Users/you/.anb/alice/exec-allowlist.rules
4 rules loaded, 3 findings.

🚨 line 3: script-host (DANGER)
  ^/bin/sh -c .+$	*	# debug shell
  Hint: remove this rule, OR allowlist a specific script file path (e.g. ^/bin/sh /Users/me/safe.sh$	KEY) instead of '-c'.

⚠ line 7: env-wildcard (WARNING)
  ^/usr/bin/curl .+$	*	# debug curl
  Hint: list specific env names (e.g. AUTH_TOKEN) unless the binary truly needs unrestricted env.

ℹ line 12: no-label (INFO)
  ^/usr/bin/cat .+$	K
  Hint: add `\t# <label>` as third column for audit attribution.

Summary: 4 rules, 1 danger, 1 warnings, 1 info
```

**Severities:**

| Level | When | Exit code (default) | Exit code (`--strict`) |
|---|---|---|---|
| `DANGER` | regex matches everything, or covers a script-host with arbitrary `-c` argument | 1 | 1 |
| `WARNING` | env column is `*`, or regex has unescaped `.` in a path component | 0 | 2 |
| `INFO` | rule has no `# label` | 0 | 0 |

Plus parse errors (lines that fail `aclrules.Parse`) always exit 1.

**Flags:**

- `--file PATH` — check a specific file (useful for testing candidate rules before committing)
- `--strict` — exit non-zero on WARNINGs too (suitable for CI / pre-commit hooks)

**When to run:** before adding a hand-written rule, before a release, or in a pre-commit hook on the same machine that holds the rules file. The check is purely local — no daemon round-trip, no decrypts.

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `ANB_BOB_DIR` | `~/.anb/bob` | Bob's state directory |
| `ANB_ALICE_DIR` | `~/.anb/alice` | Alice's state directory |
| `ANB_BOB_PASSWORD` | _(prompt)_ | Master password for `bob init`/`serve` (automation; otherwise prompted on a TTY) |
| `ANB_PAIR_CODE` | _(prompt)_ | 8-digit pairing code for `alice install-cert` (automation; otherwise prompted on a TTY) |

`--dir` overrides the state directory on any command.

### Authorization (`authz.json` in Bob's dir)

```json
{
  "rules": {
    "alice-laptop": ["*"],
    "agent-ci":     ["ci-", "deploy-"]
  }
}
```

`rules` maps an identity (client-cert CommonName) to allowed key prefixes
(`"*"` = all). **If `authz.json` is absent, Bob runs allow-all** and logs a
warning — fine for first-run, configure it before production.

---

## Remote deployment

Bob is designed to run anywhere reachable. For a remote/cloud Bob:

1. `bob init --host bob.example.com` so the server cert SAN matches.
2. `bob serve --addr :8443` behind your firewall / VPN.
3. Each Alice enrolls with `--bob bob.example.com:8443 --server-name bob.example.com`.

Because trust comes entirely from the private CA, you don't need public DNS or
ACME. Running Bob over a private overlay (e.g. WireGuard/Tailscale) adds an
encrypted, node-authenticated transport beneath the application-layer mTLS.

---

## Testing

```sh
go test ./...        # unit + library-level e2e over real loopback mTLS
go vet ./...
gofmt -l .
```

`e2e/full_test.go` exercises the whole stack (set → read/redact → write/restore,
locked refusal) against a real Bob over mTLS.

---

## Status & roadmap

v2 is functional. Not yet implemented (planned):

- Bob KEK sealed to a TPM / cloud KMS for unattended restart (v2 still
  unlocks with an operator master password).
- Alice's client key on hardware (PKCS#11 / Secure Enclave).
- Certificate revocation lists / short-lived client certs.
- `alice exec` allowlist patterns: wildcards / regex / args-prefix matching
  (v2 is strict byte-for-byte; per-entry patterns are a future iteration).

---

## License

See [LICENSE](LICENSE) (to be added).
