# AnB

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
  `get`, `rm`, `import`, `init`, `scan`, `require-presence`.
- **Redaction engine** — `read` replaces known secret values and high-entropy
  unvaulted tokens with `<agent-vault:key>` / `<agent-vault:UNVAULTED:sha256:…>`
  placeholders; `write` restores them. Secret values never appear in `read`/`scan`
  output.
- **Safe / sensitive split** — safe commands (`read`/`write`/`has`/`list`) work
  for agents without a TTY; sensitive commands (`set`/`get --reveal`/…) require an
  interactive terminal, so an agent (even under prompt injection) structurally
  cannot exfiltrate plaintext.
- **Mutual TLS with a private CA** — no public CA, no ACME. Bob mints its own CA,
  server cert, and signs each client's CSR. Runs over any network (LAN, VPN,
  internet).
- **Per-identity authorization** — map each identity to the key prefixes it may
  touch, plus an optional presence allowlist for gated keys. Every request is
  audited.
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
- Presence gating here is a **Bob-side policy** (identity allowlist + audit), not
  device biometrics.

---

## Install

Requires **Go 1.23+**.

```sh
git clone <repo> AnB && cd AnB

# build both binaries into ./bin
go build -o bin/bob   ./cmd/bob
go build -o bin/alice ./cmd/alice

# …or install onto your PATH
go install ./cmd/bob
go install ./cmd/alice
```

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

Hand `ca.crt` to each Alice out of band (it's the public trust anchor).

### 2. Enroll Alice

```sh
# on Alice's machine: generate a keypair + CSR, install the CA, save the profile
alice enroll \
  --identity alice-laptop \
  --bob bob.internal:8443 \
  --server-name bob.internal \
  --ca ./ca.crt
#   → writes client.key (0600), client.csr, ca.crt, config.json

# send client.csr to the Bob operator, who reviews the identity and signs it:
bob sign-csr alice-laptop.csr --out alice-laptop.crt

# back on Alice's machine, install the signed cert:
alice install-cert ./alice-laptop.crt

# verify the whole chain end-to-end
alice status
#   Identity:   alice-laptop
#   Bob:        bob.internal:8443 (server-name bob.internal)
#   Bob status: unlocked
```

### 3. Daily use

```sh
# store a secret (interactive, human only — encrypted by Bob, ciphertext stored locally)
alice set stripe-key
alice set db-url --from-env DATABASE_URL
alice set webhook --require-presence --reason "prod webhook signer"

# list / inspect
alice list                       # gated keys marked [presence]
alice get stripe-key             # metadata only
alice get stripe-key --reveal    # shows the value (TTY required)

# agents use the safe commands — secrets stay redacted
alice read config.yaml           # secret values → <agent-vault:key>
echo 'token: <agent-vault:stripe-key>' | alice write config.yaml

# audit a file for vaulted + unvaulted secrets
alice scan config.yaml

# bulk import a .env, toggle presence, remove
alice import .env
alice require-presence stripe-key --on
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

It bulk-imports ordinary keys (restores `<agent-vault:key>` placeholders into a
temp file, runs `alice import --min-length 1`, then `rm -P`s it) and migrates
presence-gated keys interactively so their plaintext never touches disk. Key
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
| `bob sign-csr <csr> [--out F] [--ttl-days N]` | Sign an Alice CSR → client cert |
| `bob serve [--addr :8443] [--ttl SECONDS] [-D] [--log FILE]` | Unlock + run the mTLS oracle (`-D` detaches into the background) |

### alice — safe (agent + human, no TTY)

| Command | Description |
|---|---|
| `alice read <file>` | Print the file with secrets redacted |
| `alice write <file> [--content C]` | Restore `<agent-vault:…>` placeholders (stdin if no `--content`) |
| `alice has <keys...> [--json]` | Check existence (local metadata) |
| `alice list [--json]` | List key names; gated keys marked `[presence]` |
| `alice status` | Enrollment + Bob reachability/unlock state |

### alice — sensitive (human only, TTY required)

| Command | Description |
|---|---|
| `alice set <key> [--desc D] [--from-env V] [--stdin] [--force] [--require-presence] [--reason R]` | Store a secret (encrypted by Bob) |
| `alice get <key> [--reveal]` | Metadata, or the value with `--reveal` |
| `alice rm <key>` | Remove a secret |
| `alice import <file> [--min-length N]` | Bulk-import a `.env` file |
| `alice init` | Initialize an empty local vault |
| `alice scan <file> [--json]` | Audit a file for vaulted + unvaulted secrets |
| `alice require-presence <key> --on\|--off [--reason R]` | Toggle presence policy on a key |

### alice — setup

| Command | Description |
|---|---|
| `alice enroll --identity N --bob HOST:PORT --ca ca.crt [--server-name SAN]` | Generate keypair + CSR, install CA, save profile |
| `alice install-cert <client.crt>` | Install the signed client cert |

Flags may appear before or after positional arguments.

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `ANB_BOB_DIR` | `~/.anb/bob` | Bob's state directory |
| `ANB_ALICE_DIR` | `~/.anb/alice` | Alice's state directory |
| `ANB_BOB_PASSWORD` | _(prompt)_ | Master password for `bob init`/`serve` (automation; otherwise prompted on a TTY) |

`--dir` overrides the state directory on any command.

### Authorization (`authz.json` in Bob's dir)

```json
{
  "rules": {
    "alice-laptop": ["*"],
    "agent-ci":     ["ci-", "deploy-"]
  },
  "presence": { "allow": ["alice-laptop"] }
}
```

`rules` maps an identity (client-cert CommonName) to allowed key prefixes
(`"*"` = all). `presence.allow` lists identities permitted to decrypt
presence-gated keys. **If `authz.json` is absent, Bob runs allow-all** and logs a
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
presence gating, locked refusal) against a real Bob over mTLS.

---

## Status & roadmap

v1 is functional. Not yet implemented (planned):

- Bob KEK sealed to a TPM / cloud KMS for unattended restart (v1 unlocks with an
  operator master password).
- Real device-biometric presence; Alice's client key on hardware (PKCS#11 / Secure
  Enclave).
- Certificate revocation lists / short-lived client certs.

---

## License

See [LICENSE](LICENSE) (to be added).
