# Alice and Bob

> ## ⚠ SECURITY ADVISORY — affects v2.0 through v2.5 (fixed in v2.6.0)
>
> Bob's daemon (`cmd/bob/main.go::cmdServe`) called
> `store.Hold(mk, …); crypto.Wipe(mk)` — but `Hold` stored the slice by
> reference and `Wipe` zeroed the underlying array, so the daemon's
> in-memory K became 32 bytes of zeros immediately after startup.
> **Every secret stored or retrieved by v2.0–v2.5 Bob was encrypted under
> an all-zero AES-256 key.** Anyone with read access to `vault.json`
> could decrypt every entry offline without Bob, the master password,
> or any network access.
>
> **Severity**: Catastrophic for the design intent. Practical impact for
> single-user laptops is bounded by the same-uid trust boundary (anyone
> who can read `vault.json` already runs as the secret-owning user), but
> the project's promise of "vault.json is ciphertext, Bob holds the
> KEK" was never actually delivered.
>
> **Fix**: v2.6.0 stops calling `Wipe` after `Hold` and makes `Hold`
> **defensively copy** the key bytes (so an aliasing footgun can't
> regress). A regression test pins the invariant.
>
> **Migration**: a one-shot client-side migrator is shipped as
> `alice rekey-from-zero`. It locally GCM-Opens each vault entry under
> the all-zero K, sends the plaintext to (fixed) Bob to re-encrypt
> under the real master key, and writes the new ciphertext back.
> Idempotent; supports `--dry-run`. **All v2.0–v2.5 operators MUST
> run this once after upgrading to v2.6**, otherwise existing
> vault.json entries stay decryptable via the public zero key.
>
> See "Master key rotation" below for the broader v2.6 versioned-K
> story; the zero-K bug is unrelated to that work but surfaced during
> v2.6 testing because v2.6 stopped using zero K and the existing
> entries no longer decrypted.

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
- **Safe / sensitive split** — safe commands (`read`/`write`/`has`/`list`) work
  for agents without a TTY; sensitive commands (`set`/`get --reveal`/…) require an
  interactive terminal, so an agent (even under prompt injection) structurally
  cannot exfiltrate plaintext.
- **Agent-safe exec (operator-allowlisted)** — `alice exec --env KEY=<agent-vault:k> -- <cmd> <args>`
  is default-deny since v2.0.0. Operator pre-blesses exact
  (cmd, args, env_keys) triples in `~/.anb/alice/exec-allowlist.json`.
  Matched invocations resolve placeholders into the child's env and
  `syscall.Exec` the child without further prompting (agent-autonomous);
  any change to the triple — including whitespace, arg order, or env
  names — requires a new entry. Companion: `alice write --quiet`
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
# Note the /v2/ in the path — Go modules require the major-version
# suffix for v2+. Tags v2.0.0 and v2.1.0 predate the /v2 module path
# and CANNOT be installed via `go install`; use v2.2.0 or later.
go install github.com/kaka-milan-22/AnB/v2/cmd/bob@v2.2.0
go install github.com/kaka-milan-22/AnB/v2/cmd/alice@v2.2.0

# …or build from a local clone of the v2.2.0 tag
git clone --branch v2.2.0 https://github.com/kaka-milan-22/AnB.git && cd AnB
go build -o bin/bob   ./cmd/bob
go build -o bin/alice ./cmd/alice
```

Replace `v2.2.0` with `@latest` to track unreleased changes on `main`.

After install, `alice version` / `bob version` (also `-V` / `--version`)
prints the build info — tag, commit, Go version, platform — read from the
binary's embedded `runtime/debug.BuildInfo`.

---

## Quick start

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

# v2.0.0+: alice exec is default-deny via ~/.anb/alice/exec-allowlist.json.
# `alice enroll` scaffolds an empty {"allow":[]} for you. To allow a new
# invocation: run it once. The deny error shows you the exact JSON
# triple to add. On a TTY (interactive operator), alice also prompts
# `Type 'yes' to confirm` — answering yes atomically appends the entry
# and exits with "re-run to execute"; you re-run the command manually.
# Non-TTY callers (agents, pipes) never see the prompt — hard-deny only.
#
# NOTE: single-quote --env values so the shell doesn't expand `<` / `>`.
alice exec --env 'GH_TOKEN=<agent-vault:gh-pat>' \
  -- /opt/homebrew/bin/gh api user

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

### alice — safe (agent + human, no TTY)

| Command | Description |
|---|---|
| `alice read <file>` | Print the file with secrets redacted |
| `alice write <file> [--content C] [--quiet]` | Restore `<agent-vault:…>` placeholders (stdin if no `--content`). Status lines go to stderr; `--quiet` suppresses them. |
| `alice has <keys...> [--json]` | Check existence (local metadata) |
| `alice list [--json]` | List all stored key names (local metadata; no Bob round-trip) |
| `alice status` | Enrollment + Bob reachability/unlock state |
| `alice exec [--env KEY=V]... [--reason R] -- <cmd> [args...]` | Match against `~/.anb/alice/exec-allowlist.json`; on hit, resolve placeholders and `syscall.Exec` the child. Default-deny — see Authorization / allowlist sections for the JSON schema. Allowlist entries may carry an optional `"label"` field used in audit/error output and as the default `--reason` fallback. |

### alice — sensitive (human only, TTY required)

| Command | Description |
|---|---|
| `alice set <key> [--desc D] [--from-env V] [--stdin] [--generate] [--style S] [-l N] [--force]` | Store a secret (encrypted by Bob); `--generate` makes a random value instead of entering one |
| `alice get <key> [--reveal] [--reason R]` | Metadata, or the value with `--reveal`. `--reason` is logged in Bob's ALLOW audit line. |
| `alice rm <key>` | Remove a secret |
| `alice gen [--style S] [-l N] [-n N]` | Generate & print random password(s) — see below |
| `alice import <file> [--min-length N]` | Bulk-import a `.env` file |
| `alice init` | Initialize an empty local vault |
| `alice scan <file> [--json]` | Audit a file for vaulted + unvaulted secrets |
| `alice template <src> <dst> [--mode 0600] [--owner u:g] [--reason R]` | Render `<src>`'s `<agent-vault:k>` placeholders into `<dst>` with explicit mode (default `0600`) and optional ownership. Atomic write. See "Templating" below. |
| `alice shell [--env K=V]... [--reason R] [-- shell args...]` | Spawn an interactive sub-shell with `--env` (placeholder-restored) injected. TTY-only (no allowlist); sets `ALICE_SHELL=1`. See "Sub-shell" below. |
| `alice rekey-status` | Show per-K-version entry counts in this alice's vault.json (no Bob round-trip). |
| `alice rekey [--reason R]` | Force-migrate every vault entry to Bob's current K version. |

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
scripts/anb-backup.sh bob /tmp/before-rotate.age      # 0. recovery snapshot

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
