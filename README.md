# AnB — Alice and Bob

> A **client/server secrets vault for the age of AI agents**. Alice (the CLI
> your agents call) only ever sees ciphertext. Bob (the KMS daemon) holds the
> master key and answers encrypt/decrypt requests over mTLS. The key never
> leaves Bob — not via stdout, not via temp files, not via the agent's tool
> output that gets streamed back into the LLM context.

[![Go 1.26+](https://img.shields.io/badge/go-1.26+-blue.svg)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Beta](https://img.shields.io/badge/status-beta-orange.svg)](#whats-next)
[![Release: v3.3.2](https://img.shields.io/badge/release-v3.3.2-green.svg)](https://github.com/kaka-milan-22/AnB/releases/latest)

---

## Why this exists

In 2026, an LLM agent can already read your config files, decide what to
deploy, and call kubectl on your behalf. The credential stores you trust today
— `~/.aws/credentials`, `.env` files, raw env vars, password managers behind
GUI prompts — were built for **humans typing and clicking**. Hand the
keyboard to an agent and three failure modes show up that no traditional
vault was designed to handle:

| Failure mode | What happens with a typical secrets store |
|---|---|
| **Plaintext-on-disk** | `.env` / `~/.aws/credentials` / kubeconfig with embedded tokens — any agent that can `cat` reads them straight |
| **Stdout exfil** | Agent runs `op read op://Vault/Item/password` (or equivalent), the secret lands in the agent's tool output, the agent's framework streams that back to the LLM provider as context |
| **Argv leak** | Agent runs `mycli --token sk-…`, the token shows up in `ps`, in shell history, in audit logs, and in any sibling process's `/proc/PID/cmdline` |

AnB is built **agent-first**. Secrets live encrypted in `vault.json` on the
agent's machine. The master key sits in a separate daemon process behind
mTLS. Agents call alice to **inject** secrets into a target subprocess's
environment via `syscall.Exec` — the secret never appears in alice's stdout,
never in argv, never in shell history, and never in the agent's tool-output
context. A four-layer defense stack catches a different class of failure on
every call.

## How it works

```
                ┌──────────────────────────────────────────────────────────┐
                │  LLM agent (Claude Code / Cursor / cron / arbitrary)     │
                │      ↓  shell call: alice exec --env K=<placeholder> -- │
                └──────────────────────────────────────────────────────────┘
                                          │
   ┌──────────────────────────────────────┼──────────────────────────────────────┐
   │                        alice CLI — 4-layer safety stack                     │
   │                                                                             │
   │   1. TTY gate     sensitive ops (set/get --reveal/import) refuse non-TTY    │
   │   2. allowlist    `alice exec` runs ONLY commands matching a regex rule     │
   │   3. redaction    `read` substitutes secrets out; `write` substitutes in    │
   │   4. injection    secret → child env via syscall.Exec; never argv, never    │
   │                   alice stdout, never the agent's tool-output context       │
   └─────────────────────────────────────────────────────────────────────────────┘
                                          │
                            mTLS (private CA, mutual cert auth)
                                          │
                                          ▼
                          ┌──────────────────────────────┐
                          │  bob — KMS daemon            │
                          │  • master key in mlock'd mem │
                          │  • Argon2id-wrapped at rest  │
                          │  • per-identity authz        │
                          │  • JSON audit log            │
                          │  • per-identity rate limit   │
                          └──────────────────────────────┘
                                          │
                                          ▼
                                   ┌─────────────┐
                                   │ envelope.json│
                                   │ (encrypted)  │
                                   └─────────────┘
```

The master key lives only in Bob's mlock'd memory. It is wrapped at rest with
Argon2id under an operator-typed master password; that password is asked once
at `bob serve` startup and never touches disk. Alice carries only the
ciphertext of individual secrets in `vault.json` (also AES-256-GCM, sealed by
Bob, key id versioned for rotation). Same envelope-encryption pattern as AWS
KMS or HashiCorp Vault Transit, scoped to a single self-hosted pair of
binaries you fully control.

## How it compares

|                                     | `.env` / `~/.aws/credentials` | 1Password CLI | `pass` / GPG | agent-vault (deprecated) | **AnB** |
|-------------------------------------|:---:|:---:|:---:|:---:|:---:|
| Encrypted at rest                   | ✗ | ✓ | ✓ | ✓ | ✓ |
| Key never on the agent's machine    | ✗ | ✓ (cloud-held)| ✗ | ✗ | ✓ (own daemon) |
| Secret never to alice stdout        | ✗ | ✗ | ✗ | ✗ | ✓ |
| Inject directly to child env (no argv leak) | ✗ | ✗ | ✗ | ✓ | ✓ |
| Allowlist of which child commands can be run | ✗ | ✗ | ✗ | ✗ | ✓ |
| Per-identity authorization (multi-alice) | ✗ | ✓ | ✗ | ✗ | ✓ |
| Per-identity rate limit             | ✗ | ✗ | ✗ | ✗ | ✓ |
| Redaction engine (read/write/scan)  | ✗ | ✗ | ✗ | ✓ | ✓ |
| Append-only audit log (JSON)        | ✗ | partial | ✗ | ✗ | ✓ |
| Versioned master keys + lazy rewrap | ✗ | ✓ | ✗ | ✗ | ✓ |
| BIP-39/44 HD wallet built in        | ✗ | ✗ | ✗ | ✗ | ✓ |
| Self-hosted, no cloud round-trip    | ✓ | ✗ | ✓ | ✓ | ✓ |

AnB is the spiritual successor to
[agent-vault](https://www.npmjs.com/package/@kaka-milan-22/agent-vault)
(TypeScript): same command surface (`read`/`write`/`has`/`list`/`set`/`get`/
`rm`/`import`/`exec`), same redaction model, same `<agent-vault:key>`
placeholder grammar — but the master key is now split out into Bob, no longer
sitting next to the ciphertext on the client.

## Who this is for

- ✓ Operators running LLM agents that touch credentials — anything from API
  tokens for cloud providers to database passwords to SSH keys
- ✓ Anyone uneasy about giving an agent shell access to a machine where
  `~/.aws/credentials` and `kubeconfig` sit unencrypted
- ✓ Teams who need an audit trail of "which agent identity decrypted which
  key at which timestamp, for what stated reason"
- ✓ Cryptocurrency holders who want a CLI HD wallet that stores the BIP-39
  mnemonic under the same KMS-grade custody as their other secrets
- ✗ Not a password manager for humans (no GUI, no browser autofill — use
  Apple Passwords / 1Password / KeePassXC for those)
- ✗ Not a cloud-secrets service (no shared multi-machine sync; one bob per
  machine — though many alices can talk to one bob over the network)

## Quick demo (~5 minutes)

```sh
# 1. Install both binaries
go install github.com/kaka-milan-22/AnB/v3/cmd/alice@latest
go install github.com/kaka-milan-22/AnB/v3/cmd/bob@latest

# 2. Set up Bob (the KMS daemon). Run these once on the operator's machine:
bob ca init                                # private CA — trust root for every identity
bob init --host localhost,127.0.0.1        # wrap a master key, mint server cert
                                           # → prompts for master password
bob serve -D --addr 127.0.0.1:8443         # daemonize, listen for alices
                                           # → ✓ bob daemonized (pid N) → ~/.anb/bob/bob.log

# 3. Enroll Alice (the client). On the same machine for now:
alice enroll --bob 127.0.0.1:8443 \
             --ca ~/.anb/bob/ca.crt \
             --identity my-laptop           # generates client.key (0600) + client.csr

# 4. Have Bob sign Alice's CSR:
bob sign-csr ~/.anb/alice/client.csr        # → outputs pairing code on Bob's TTY
                                            #   feed the code back when Alice asks

# 5. Install the signed cert back on Alice:
alice install-cert ~/.anb/bob/signed/my-laptop.crt
alice status                                # → Bob: unlocked  ✓

# 6. Put a secret in the vault (TTY only — Alice will refuse without one)
alice set my-api-token                       # prompts for the value, sealed by Bob

# 7. Have an agent USE it without ever seeing the plaintext:
alice exec --env API_TOKEN='<agent-vault:my-api-token>' -- \
    curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/me
#   ↑ alice resolves the placeholder, syscall.Execs curl with API_TOKEN
#     in its env. Plaintext appears only inside curl's process memory.
```

For the full command tree see [Daily commands](#daily-commands) below.

## What you get today

- **Core secrets vault** — `set` / `get` / `rm` / `list` / `has` / `import` —
  AES-256-GCM sealed by Bob, per-secret ciphertext + metadata on the client
- **Agent-safe injection** —
  - `alice exec --env K=<agent-vault:key> -- cmd` resolves the placeholder
    against Bob, `syscall.Exec`s the child with the resolved value in its
    env (never alice's argv, never alice's stdout)
  - `alice shell --env K=<placeholder>` for an interactive sub-shell with
    injected env (TTY-only, no allowlist)
  - `alice template src dst` renders `<agent-vault:k>` placeholders in
    config-file templates with atomic write + mode/owner control
- **Redaction engine** — `alice read` substitutes known secret values and
  high-entropy unknown tokens with `<agent-vault:…>` placeholders so the
  output can be shown to an agent. `alice write` restores them on the way out
  to the child process. `alice scan` audits a file for accidentally-embedded
  secrets
- **Per-identity authorization** — `authz.json` maps each client cert's
  CommonName to a set of allowed key-name prefixes (or `*`). Unknown
  identity = denied; valid identity outside its allowlist = denied + audit
- **Regex execution allowlist** — `~/.anb/alice/exec-allowlist.rules`
  declares which command lines `alice exec` may run, with which env-name
  set, with what audit label. Unmatched = TTY-prompt-to-confirm (humans)
  or hard-deny (agents). `alice allowlist-check` lints the file
- **Versioned master keys + lazy rewrap** — `bob rotate-master-password` /
  `bob rotate-master-key` add a fresh K; old ciphertext keeps decrypting and
  gets re-sealed under the new K on the next read (transparent migration).
  `--finalize <id>` retires a K version when usage has wound down
- **JSON audit log** — every encrypt/decrypt/deny/rate-limit/key-rewrap
  event gets one JSON line in `~/.anb/bob/bob.log`. Per-call `--reason`
  string lands as a free-text "why" field for incident reconciliation
- **Per-identity rate limit** — token-bucket cap (default 100 decrypts/min)
  on `decrypt` and `decryptMany`; configurable per-identity via authz.json
- **BIP-39/44 Ethereum HD wallet** — `alice eth new` generates a 24-word
  mnemonic, derives the address at `m/44'/60'/0'/0/0`, stores the mnemonic
  as a normal Bob-sealed vault entry. `alice eth address --index N` derives
  on demand; `alice eth list` enumerates all wallets. EIP-55 checksum on
  every output. Multi-wallet via `--name`
- **Password generator** — `alice gen` with 5 styles: `apple` (Apple-style
  alphanumeric groups), `full` (alnum + symbols), `passphrase` (EFF
  wordlist), `pin` (digits), `aes256` (32-byte base64url — direct fit for
  AES-256 / ChaCha / Fernet / encipherr keys)

## Install

```sh
# Both binaries from the latest release
go install github.com/kaka-milan-22/AnB/v3/cmd/alice@latest
go install github.com/kaka-milan-22/AnB/v3/cmd/bob@latest

# Verify
alice version
bob version
```

> **Note**: Go modules require the major-version suffix for v2+. v3.0.0+
> lives under `/v3/`; tags v2.2.0–v2.6.x are under `/v2/`; tags v2.0.0
> and v2.1.0 predate the suffix and cannot be `go install`ed. Always
> use the `/v3/` path for new installs.

For a local clone (development):

```sh
git clone https://github.com/kaka-milan-22/AnB.git
cd AnB
go install ./cmd/alice ./cmd/bob   # → $GOBIN (or ~/go/bin)
```

## One-time setup

### Bob (operator, the KMS side)

```sh
# 1. Create the private CA. Trust root for every identity (alice clients +
#    bob's own server cert). Done ONCE per deployment.
bob ca init

# 2. Generate the master key, wrap it with the operator's password, mint
#    bob's server cert. --host lists the SANs alices will verify; add real
#    hostnames/IPs if bob serves over the network.
bob init --host localhost,127.0.0.1
#   → prompts for the master password (or set $ANB_BOB_PASSWORD for automation;
#     v3.3.2+ pops the env var immediately after read)

# 3. Run the oracle. Foreground for development, -D to daemonize.
bob serve --addr 127.0.0.1:8443                  # foreground
bob serve -D --addr 127.0.0.1:8443               # daemonized
#   → ✓ bob daemonized (pid N) → ~/.anb/bob/bob.log
#     stop with: kill $(cat ~/.anb/bob/bob.pid)  (SIGTERM zeroizes the key)

# 4. (optional) Write an authz.json policy to lock down per-identity access.
#    Without authz.json, bob defaults to ALLOW-ALL with a WARN_ALLOW_ALL on
#    every startup — fine for first-run dev, NOT fine for multi-identity.
cat > ~/.anb/bob/authz.json <<'JSON'
{
  "rules": {
    "my-laptop":    ["*"],
    "agent-ci":     ["ci-", "deploy-"],
    "remind-bot":   ["reminder-"]
  },
  "rate_limits": {
    "default":     100,
    "my-laptop":   1000,
    "agent-ci":    50
  }
}
JSON
# Restart bob to pick up authz changes.
```

### Alice (agent side, one per identity)

```sh
# 1. Generate a keypair + CSR, install the CA, save the bob endpoint
alice enroll --bob 127.0.0.1:8443 \
             --ca ~/.anb/bob/ca.crt \
             --identity my-laptop
#   → ~/.anb/alice/{client.key (0600), client.csr, ca.crt, config.json}

# 2. Send client.csr to the operator. Operator runs:
bob sign-csr ~/.anb/alice/client.csr
#   → bob prints:
#       CSR identity:  my-laptop
#       CSR pubkey fp: 5f8a…c1   (sha256 of SubjectPublicKeyInfo)
#       Pairing code:  47281930  (expires in 10m)
#   → operator reads pairing code to alice operator out-of-band
#     (Signal / phone / sticky note), alice operator types it in to confirm.

# 3. Operator hands back the signed cert. Alice installs it:
alice install-cert ~/.anb/bob/signed/my-laptop.crt
#   → ✓ enrolled as 'my-laptop' (cert valid until 2027-05-30T14:23:00Z)

# 4. Confirm wiring
alice status
#   → Identity:   my-laptop
#     Bob:        127.0.0.1:8443 (server-name localhost)
#     Bob status: unlocked
```

## Daily commands

```sh
# ── Sensitive ops (human-only, TTY required) ──

alice set my-api-token                       # interactive prompt for value
alice set my-api-token --from-env VAR        # value from $VAR (avoids paste history)
echo "$VALUE" | alice set --stdin --force my-api-token   # pipe in (v3.2+: stdout-TTY relaxed)
alice set --generate my-api-token            # alice generates the value
alice set --generate --style aes256 enc-key  # 32-byte base64url (AES-256 / ChaCha key)
alice gen --style passphrase -n 3            # show 3 passphrase candidates (no store)

alice get my-api-token                       # metadata only (set timestamp, description)
alice get my-api-token --reveal              # actual value to TTY (stdout-TTY required)
alice rm my-api-token
alice import file.env                        # bulk KEY=value lines
alice scan config.yaml                       # audit a file for embedded secrets

# ── Agent-safe ops (no TTY required, includes redaction) ──

alice list                                   # all key names
alice list --json                            # machine-readable, includes desc

alice has my-api-token db-password           # exit 0 if all present, 1 if any missing

alice read app.yaml > app.redacted.yaml      # replaces secret values w/ <agent-vault:k>
alice scan app.yaml                          # report secrets found in the file
alice write app.yaml < app.redacted.yaml     # restore placeholders (on the way out)

# ── Secret injection (the agent path) ──

alice exec --env API_TOKEN='<agent-vault:my-api-token>' -- \
    curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com
#   ↑ alice resolves the placeholder, syscall.Execs curl with API_TOKEN in env.
#     Plaintext lives only in curl's process. Allowlist must match the command.

alice exec --env API_TOKEN='<agent-vault:my-api-token>' \
           --env DB_PASS='<agent-vault:db-password>' \
           --reason "deploy v1.2" -- \
    ./deploy.sh                              # --reason lands in bob's audit log

alice shell --env API_TOKEN='<agent-vault:my-api-token>'
#   ↑ interactive sub-shell with API_TOKEN injected. TTY-only, no allowlist.
#     Exit when done; child shell can do anything; alice doesn't supervise.

alice template app.yaml.tmpl app.yaml --mode 0600 --owner $USER
#   ↑ renders <agent-vault:k> placeholders into app.yaml atomically.
#     Useful for systemd units, k8s manifests, etc.

# ── Master key rotation (operator, on bob's machine) ──

bob list-keys                                # show held K versions, mark current
bob rotate-master-password                   # default: change password AND add new K
bob rotate-master-password --keep-key        # legacy: change password only
bob rotate-master-key                        # add fresh K, same password
bob rotate-master-key --finalize 1           # destroy K_1 (after rekey-status confirms 0 entries on it)

# ── Lazy rewrap migration (on the alice side) ──

alice rekey-status                           # how many entries are on each K version
alice rekey                                  # force-migrate every entry to bob's current K

# ── Ethereum HD wallet (BIP-39 / BIP-44 / EIP-55) ──

alice eth new                                # 24-word mnemonic + first address (default --name=eth)
alice eth new --name eth-cold --words 24     # second independent wallet
alice eth address --index 0                  # m/44'/60'/0'/0/0
alice eth address --name eth-cold --index 5  # m/44'/60'/0'/0/5 of the cold wallet
alice eth list                               # every ETH wallet + /0 address
alice eth list --include wallet-main-mnemonic  # pull in alice-set mnemonics without our marker
alice eth show --reveal-mnemonic             # TTY-only — print the 24 words
alice eth import --name eth-restored         # paste a mnemonic to restore an existing wallet
```

See [HD wallet](#hd-wallet-alice-eth) for the full wallet story.

## HD wallet (`alice eth`)

AnB v3.3+ ships a BIP-39/44 Ethereum HD wallet inside alice. The mnemonic is
the only piece of state stored on disk — it lives as a normal Bob-encrypted
vault entry. Addresses, private keys, and (future) signatures all derive on
demand from the stored mnemonic; nothing is cached. Same model as MetaMask,
Trezor Suite, Ledger Live.

### Pipeline

```
mnemonic (24 words)
   │ BIP-39 PBKDF2-HMAC-SHA512(salt="mnemonic", 2048 rounds)
   ↓
seed (64 B)
   │ BIP-32 master derive
   ↓
master key (32 B + chain code)
   │ BIP-44 path m/44'/60'/0'/0/N
   ↓
child private key (32 B)
   │ secp256k1 scalar mul G
   ↓
uncompressed public key (64 B)
   │ keccak256, last 20 B
   ↓
ETH address
   │ EIP-55 mixed-case checksum
   ↓
0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

Verified against the canonical BIP-39 12-word vector (`abandon × 11 + about`
→ `0x9858EfFD…aEda94`) and 8 EIP-55 official vectors. The derivation library
is `tyler-smith/go-bip32` + `btcsuite/btcd/btcec/v2` (pure Go, small surface;
deliberately **not** `go-ethereum/crypto`).

### Sample session

```text
$ alice eth new
✓ Stored mnemonic under "eth" (encrypted by Bob).

Mnemonic — write this down NOW (it is the ONLY backup outside the vault):

   1. canyon     2. wrist      3. drift     4. silly
   …

First address (m/44'/60'/0'/0/0):  0xAbC1…D42a

To derive more addresses:
  alice eth address --name eth --index 1
  alice eth address --name eth --index 2

$ alice eth address --index 5
0x9FfE7C…4567

$ alice eth show
Vault entry:      eth
Set at:           2026-05-30T22:15:00Z
Description:      ETH BIP-39 mnemonic (24 words, derive m/44'/60'/0'/0/N)
Address (idx 0):  0xAbC1…D42a
(Use --reveal-mnemonic on a TTY to print the 24 words.)
```

### What's deliberately NOT here

- **Signing transactions**. AnB stays in custody territory. To send ETH or
  interact with contracts, hand the mnemonic to a signing CLI via `alice
  exec`: `alice exec --env ETH_MNEMONIC='<agent-vault:eth>' -- cast wallet
  sign-tx --mnemonic-env ETH_MNEMONIC …`. The
  [wallet](https://github.com/kaka-milan-22/wallet) project is built on top
  of this pattern.
- **Non-Ethereum chains**. ETH (and every EVM chain — Polygon, Arbitrum,
  Optimism, Base — shares the same address space) is supported. Bitcoin /
  Solana / etc. require different derivation curves and address formats —
  out of scope.

## Master key rotation (v2.6+)

```
                          envelope.json (on disk)
                          ┌─────────────────────┐
   bob rotate-master-key  │ K_1 ←  ←  ←  ←  ←   │
   ─────────────────────► │ K_2 ← new, current  │   ← Bob encrypts new
                          └─────────────────────┘     entries under K_2
                                    │
                                    │  alice reads OLD K_1 ciphertext
                                    ▼
                          ┌─────────────────────┐
                          │ vault.json          │
                          │ • entryA  v1:cipher │   ← still decrypts fine
                          │ • entryB  v1:cipher │     Bob rewrap-encodes
                          │ • entryC  v1:cipher │     plaintext under K_2,
                          └─────────────────────┘     alice writes back v2:…
                                    │
                                    │  natural drift over time
                                    ▼
                          ┌─────────────────────┐
                          │ vault.json          │
                          │ • entryA  v2:cipher │   alice rekey-status → 0 on v1
                          │ • entryB  v2:cipher │       ↓
                          │ • entryC  v2:cipher │   bob rotate-master-key --finalize 1
                          └─────────────────────┘
```

Three commands cover the full rotation story:

| Command | Effect |
|---|---|
| `bob rotate-master-password` | Re-wrap K under a new password. **Default in v2.6+ also adds a fresh K**; pass `--keep-key` to fall back to v2.3 password-only rotation. |
| `bob rotate-master-key` | Add a fresh K under the **same** password — pure key rotation without touching the passphrase. |
| `bob rotate-master-key --finalize <id> [--yes]` | Irrevocably retire K_id from envelope.json and from Bob's mlock'd memory. Interactive confirmation unless `--yes`. Refuses `--finalize <current>`. |
| `bob list-keys` | Show held K versions (no password required). |

On the alice side:

| Command | Effect |
|---|---|
| `alice rekey-status` | Per-K-version count of vault.json entries (pure local scan). |
| `alice rekey [--reason R]` | Force-migrate every entry to Bob's current K (eager equivalent of lazy rewrap). |

**Lazy migration is the default.** You don't need to run `alice rekey` —
every normal `alice get` / `alice exec` triggers a rewrap on the fly if the
entry is on an old K. Run `alice rekey-status` periodically; when it shows 0
on the old version, finalize. The drift toward `current` happens
transparently as the agent does its normal work.

### When to `--finalize`

- After a personnel change (operator who knew the old password leaves)
- After a suspected compromise (the old K's material was on a disk that
  may have been imaged)
- Routinely — e.g. quarterly — so K versions don't accumulate without bound

The finalize step is destructive: any vault.json entry still encrypted under
that K becomes permanently unreadable. **Always check `alice rekey-status`
on every enrolled identity before finalizing.**

## Multi-identity setup

One bob can serve N alices, each with its own cert + authz rules. Run the
enrollment flow ([above](#alice-agent-side-one-per-identity)) once per
identity. Then in `authz.json`:

```json
{
  "rules": {
    "alice-laptop":  ["*"],
    "agent-ci":      ["ci-", "deploy-"],
    "remind-bot":    ["reminder-"]
  },
  "rate_limits": {
    "default":      100,
    "alice-laptop": 1000,
    "agent-ci":     50,
    "remind-bot":   200
  }
}
```

- Each `rules` entry is a list of key-name **prefixes** (or `"*"` for
  all). An identity outside its allowlist → DENY + audit.
- `rate_limits` are per-minute decrypt caps. Lookup order: explicit
  per-identity → `"default"` → built-in `100`.
- Encrypt operations are not rate-limited (they're TTY-driven, not
  agent-spammable).

Bob picks up `authz.json` at startup; restart `bob serve` to apply changes.

## End-to-end test

Once Bob is serving and Alice is enrolled:

```sh
alice status                                          # → Bob: unlocked
echo "my-secret-value" | alice set --stdin --force testkey
alice get testkey --reveal                            # TTY → my-secret-value
alice exec --env VAL='<agent-vault:testkey>' -- \
    sh -c 'echo "child sees: $VAL"'                   # → child sees: my-secret-value
alice eth new --name e2e-test
alice eth address --name e2e-test                     # → 0x…
alice eth list                                        # e2e-test appears
alice rm testkey
alice rm e2e-test    # cleanup
```

## Security checks

Run these before trusting the vault with real value:

```sh
# (1) vault.json is ciphertext only — no plaintext anywhere
cat ~/.anb/alice/vault.json | jq '.secrets | map(.value) | .[0]'
# → "v3:8c4f...:..." (hex ciphertext, no plaintext)

# (2) Process args carry no secrets after `alice exec`
alice exec --env TOK='<agent-vault:my-api-token>' -- sleep 30 &
ps aux | grep sleep
# → "/bin/sleep 30" — TOK is in the child's environ, NOT argv

# (3) Bob's audit log shows every decrypt
tail -5 ~/.anb/bob/bob.log | jq .
# → JSON-line audit, includes identity / op / keys / reason

# (4) Master key never on the alice side
ls -la ~/.anb/alice/
# → vault.json, client.key (0600), client.crt, ca.crt, config.json, exec-allowlist.rules
# → NO master.key, NO envelope.json — those live in ~/.anb/bob/

# (5) Bob's master key is mlock'd
ps -o rss,command $(cat ~/.anb/bob/bob.pid)
# → RSS includes the master key page, but the page is mlocked
#   (won't swap to disk under memory pressure)

# (6) Allowlist refuses unknown commands when agent calls without TTY
alice exec --env API_TOKEN='<agent-vault:my-api-token>' -- /bin/cat /etc/hosts
# → ✗ DENIED  (assuming /bin/cat isn't in your allowlist)
```

## JSON output mode

Every alice command supports `--json`:

```sh
alice list --json | jq .
# {"keys":[{"key":"my-api-token","desc":"prod API"},{"key":"db-password"}]}

alice status --json | jq .
# {"identity":"my-laptop","bob_addr":"127.0.0.1:8443","unlocked":true}
```

### Audit log format (v2.5+)

`~/.anb/bob/bob.log` is one JSON line per event. Schema:

```jsonc
{
  "ts":       "2026-05-31T00:42:01.234Z",
  "kind":     "ALLOW",          // ALLOW | DENY | RATELIMIT | KEY_REWRAP | KEY_ADDED | KEY_FINALIZED | HANDSHAKE_FAIL | DROP | PANIC | SERVING | SHUTDOWN | AUTOLOCK | WARN_ALLOW_ALL
  "identity": "my-laptop",      // cert CommonName
  "op":       "decrypt",
  "keys":     ["my-api-token"],
  "reason":   "deploy v1.2"     // operator-supplied free text (--reason flag); audit-only
}
```

`jq` cookbook:

```sh
# All denials in the last hour
jq -c 'select(.kind == "DENY" and (.ts | fromdateiso8601) > (now - 3600))' ~/.anb/bob/bob.log

# Top 10 most-accessed keys
jq -r 'select(.kind=="ALLOW") | .keys[]' ~/.anb/bob/bob.log | sort | uniq -c | sort -rn | head

# Every secret read by `agent-ci` today
jq -c 'select(.identity=="agent-ci" and .op=="decrypt")' ~/.anb/bob/bob.log

# Rewraps (indicates lazy migration is happening)
jq -c 'select(.kind == "KEY_REWRAP")' ~/.anb/bob/bob.log
```

## Agent-callable usage

Defense in depth: TTY gate + regex allowlist + redaction engine + per-identity
authz. Agents are blocked from sensitive operations by structural gates, not
honor system.

| Operation | Agent (no TTY) | Human (TTY) |
|---|---|---|
| `list` / `has` / `status` | ✓ | ✓ |
| `read` / `scan` (redacted output) | ✓ | ✓ |
| `exec` (placeholder-resolved env injection) | ✓ if allowlist rule matches | ✓ + interactive confirm on unmatched |
| `write` / `template` (placeholder restoration) | ✓ | ✓ |
| `shell` (sub-shell with --env injection) | refuse — TTY only | ✓ |
| `set` / `import` / `rm` (mutate vault) | refuse — TTY only | ✓ |
| `get` / `eth show` (metadata read) | ✓ | ✓ |
| `get --reveal` / `eth show --reveal-mnemonic` (plaintext) | refuse — stdout-TTY required | ✓ |
| `gen` (password generator) | ✓ (pipe-friendly since v3.2) | ✓ |
| `set --stdin` (programmatic write) | ✓ (since v3.2: stdout-TTY relaxed) | ✓ |
| `init` / `enroll` / `install-cert` (setup) | refuse — TTY only | ✓ |
| `eth new` / `eth import` (HD wallet creation) | refuse — TTY only | ✓ |
| `allowlist-check` (lint exec-allowlist.rules) | ✓ | ✓ |

### Allowlist rules

`~/.anb/alice/exec-allowlist.rules` declares which command lines `alice exec`
may run. One rule per line, tab-separated fields:

```
<regex>\t<env-csv>\t#<label>
```

- **regex** — Go RE2 (linear-time, no ReDoS). Implicitly anchored `^(?:…)$`.
  Matched against `shellescape(cmd) + " " + shellescape(arg1) + …` so spaces
  in args are quoted unambiguously.
- **env-csv** — comma-separated list of env-var names the rule allows the
  operator to inject. `*` allows any name. The operator's `--env KEY=…` set
  must be a subset; otherwise → DENY.
- **#label** — optional, free text. Appears in audit lines as `rule=[label]`.

Example:

```
^/Users/kaka/\.nvm/versions/node/v20\.19\.5/bin/node /Users/kaka/work/n9e/\.playwright-mcp/n9e-auth\.js$	N9E_PASSWORD,N9E_USER	# n9e-login
^/Users/kaka/\.local/bin/encipherr (decrypt|encrypt) .+$	ENCIPHERR_KEY	# encipherr-bulk-secrets
```

`alice allowlist-check` lints the file: rejects regexes that match everything
(`^.*$`, `.*`, etc.), reports per-rule WARNINGs (over-broad patterns), DANGER
findings (env=* + lax regex), and counts.

### Placeholder grammar

`alice exec` resolves only the strict pattern `<agent-vault:KEY>` (KEY is
lowercase alphanumeric + hyphens, matching the vault key format). Anything
else gets fail-closed since v3.2:

```sh
alice exec --env K='<my-key>' -- /bin/true
# ✗ --env "K=<my-key>": value contains "<my-key>" which looks like a placeholder
#   but is missing the `agent-vault:` prefix. Did you mean `<agent-vault:my-key>`?
```

This prevents the common silent-passthrough bug (operator writes `<my-key>`
expecting resolution, alice passes the literal 8-byte string to the child,
child reports "invalid key" far downstream).

## Tests

```sh
go test ./...
```

Covers the AES-GCM seal/open round-trip, BIP-39 official 12-word test vector
(`abandon × 11 + about` → `0x9858EfFD…aEda94`), 8 EIP-55 official vectors,
the v3.x defensive-copy regression (the v2.0–v2.5 zero-K bug), envelope v2→v3
migration loader, lazy rewrap path returning a re-sealed ciphertext when the
input is on a non-current K, `--finalize` refusing the current version,
allowlist regex parsing + lint dangerous-pattern detection, ETH derivation
determinism (50 redraws of the same `(mnemonic, index)` produce identical
addresses), placeholder fail-closed near-miss detection, the rate-limiter
token bucket, TTY/non-TTY gate per command. Plus a live e2e under
`e2e/full_test.go` that round-trips the full daemon flow.

## Architecture

```
cmd/
  alice/                  client CLI
    main.go               command dispatch + usage
    safe.go               read / write / has / list / status
    sensitive.go          set / get / rm / import / init / scan
    exec.go               exec (the agent injection path) + TTY-confirm fallback
    shell.go              shell (interactive sub-shell with env injection)
    template.go           template (placeholder rendering into config files)
    generate.go           gen (password generator)
    rekey.go              rekey + rekey-status
    rekey_zerok.go        one-shot v2.0–v2.5 zero-K migrator (historical fix)
    eth.go                eth new / address / show / import / list
    allowlist_check.go    allowlist-check linter
    enroll.go             enroll + install-cert (setup)
  bob/                    KMS daemon
    main.go               serve + init + ca init + sign-csr
    rotate.go             rotate-master-password + rotate-master-key + list-keys
    audit.go              JSON-lines audit emitter
internal/
  crypto/                 AES-256-GCM + Argon2id + envelope v3 schema
  keystore/               mlock'd K storage with defensive copy + version map
  proto/                  wire protocol (newline-delimited JSON requests/responses)
  server/                 bob's TLS server + dispatch + authz/audit/rate-limit plumbing
  client/                 alice's mTLS client + Decrypt/DecryptMany/Encrypt API
  authz/                  per-identity rules + rate-limit lookup
  aclrules/               exec-allowlist.rules parser + lint
  redact/                 redaction engine (placeholder grammar + restore)
  eth/                    BIP-39 mnemonic + BIP-44 derivation + EIP-55 checksum
  pwgen/                  password generator (apple/full/passphrase/pin/aes256)
  mtls/                   tls.Config builders for both ends
  localvault/             vault.json on-disk store (atomic write + fsync)
  term/                   TTY detection + password prompt + confirm
  version/                version stamping via runtime/debug.BuildInfo
e2e/
  full_test.go            full daemon round-trip integration test
scripts/
  anb-backup.sh           tar+age wrapper for cold backup of bob+alice state
```

Encrypt path: `alice` reads vault.json → grabs ciphertext → asks bob via mTLS
→ bob's `Decrypt` opens with current K (or any held K, returning rewrap under
current) → response goes back to alice → alice writes back the rewrap (if
any) for lazy migration.

Trust boundary: the operator. Bob's master password is the root of trust;
anyone who can `bob serve` + provide the password can read every secret.
Same-uid access to either machine's `~/.anb/` is bounded by file permissions
(0600 / 0700) — AnB doesn't try to defend against root or sibling processes
running as the same uid.

## Migration from agent-vault

agent-vault's vault format and AnB's are byte-compatible at the per-secret
level (same `iv:tag:ct` AES-256-GCM packed shape). To migrate:

```sh
# 1. Get the agent-vault master key (it lives in plaintext next to the vault)
AV_KEY="$(cat ~/.agent-vault/master.key)"

# 2. Initialize AnB
bob ca init && bob init --host localhost && bob serve -D --addr 127.0.0.1:8443
alice enroll … && (operator) bob sign-csr … && alice install-cert …

# 3. For each agent-vault secret, decrypt with AV_KEY locally, re-encrypt via bob
ENCIPHERR_KEY="$AV_KEY" python3 -c '
import json, base64, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = base64.urlsafe_b64decode(os.environ["ENCIPHERR_KEY"])
av = json.load(open(os.path.expanduser("~/.agent-vault/vault.json")))
for k, v in av["secrets"].items():
    # ...decrypt v["value"] with key, then `echo "$pt" | alice set --stdin --force $k`
'
```

A more polished one-shot migrator may ship as `alice import-agent-vault` in a
future release. For now the manual loop is straightforward; existing
`<agent-vault:k>` placeholders in your configs work as-is against AnB.

## What's next

See [the v3.x release notes](https://github.com/kaka-milan-22/AnB/releases)
for shipped work. On the backlog:

- **`alice audit --tail`** — stream Bob's JSON audit log over mTLS to the
  alice side. JSON format already landed in v2.5; just needs the wire op +
  alice subcommand. Important once bob runs on a remote host.
- **Certificate expiry warnings** — `alice status` / `bob serve` flag when
  client/server cert is <30d from expiry. Three-line `if`, not yet wired.
- **PKCS#11 client-key backend** — store alice's private key on a hardware
  token (Yubikey / Nitrokey / SoloKey) so an attacker with file access
  can't impersonate her identity. Designed against the PKCS#11 v3.1 spec.
- **Per-secret DEK / multi-operator quorum unlock** — v4 territory (KEK
  itself sealed to a TPM / cloud KMS / m-of-n quorum). Major architecture
  change.
- **Hardware-backed bob master key** — Secure Enclave / TPM custody for
  the KEK so `bob serve` doesn't need a typed password on startup. v4 too.

## License

[MIT](LICENSE) — use it, fork it, build on top of it.
