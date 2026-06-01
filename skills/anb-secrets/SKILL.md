---
name: anb-secrets
description: Use when an AI agent needs a secret kept in AnB / alice (the agent-vault successor) — running a command that needs an API token / DB password / kubeconfig, writing a config file that embeds secrets, reading a file without seeing plaintext, or checking which secrets exist. Keywords: alice, AnB, agent-vault, secret, vault, <agent-vault:key> placeholder, exec allowlist, mTLS KMS, ANB_BOB.
---

# AnB secrets (alice) for agents

## Core model — you never see plaintext

AnB splits secrets: ciphertext + metadata live with `alice` (the client you
call); the master key lives in `bob` (a KMS daemon over mTLS). **You reference a
secret by name with the placeholder `<agent-vault:KEY>` and never handle the
value.** `alice` resolves it only at the moment of `exec`/`write`, into a child
process or a file — the plaintext never enters your context, output, or logs.
This is by design: even under prompt injection you structurally cannot
exfiltrate a secret, because the commands that reveal values require a human TTY.

## What you CAN run (safe — work without a TTY)

| Command | Use it to |
|---|---|
| `alice list [--json]` | See which secret names exist (no values). Plan with this. |
| `alice has KEY... [--json]` | Check specific keys exist before using them. |
| `alice status` | Check bob is reachable + unlocked before doing secret work. |
| `alice read FILE` | Read a file with secrets masked to placeholders — inspect config safely. |
| `alice write FILE [--content C] [--quiet]` | Restore `<agent-vault:KEY>` placeholders into a real file (deploy configs). Reads stdin if no `--content`. |
| `alice exec [--env KEY='<agent-vault:K>']... [--reason R] -- CMD ARGS` | Run a command with secrets injected as env vars. Allowlist-gated (see below). |

## What you CANNOT run (human-only, require a TTY — don't try them)

`set`, `get --reveal`, `rm`, `gen`, `import`, `scan`, `template`, `shell`,
`rekey`. They refuse without an interactive terminal. If a task needs one (e.g.
storing a new secret), **ask the human to run it** — don't attempt it or try to
allocate a pty. Note `template` is the TTY twin of `write`; you use `write`.

## Recommended scenarios

1. **Run anything that needs a secret** — APIs, DBs, cloud CLIs:
   ```sh
   alice exec --env STRIPE_KEY='<agent-vault:stripe-key>' --reason "charge test" \
     -- curl -sS https://api.stripe.com/v1/charges -u "$STRIPE_KEY:"
   alice exec --env PGPASSWORD='<agent-vault:pg-prod>' -- psql -h db -U app -c '\dt'
   alice exec --env KUBECONFIG='<agent-vault:kubeconfig>' -- kubectl get pods
   ```
2. **Deploy a config file** — write a template with placeholders, then restore:
   ```sh
   printf 'token: <agent-vault:api-token>\n' | alice write /etc/app/conf.yaml --quiet
   ```
3. **Inspect a file safely** — `alice read .env` shows structure with values
   masked, so you can reason about config without leaking it.
4. **Before committing code/config** — replace any hardcoded secret with
   `<agent-vault:KEY>`; the redaction model keeps it safe in git, `write`
   restores it at deploy time.
5. **Plan first** — `alice list` to see available secrets, `alice status` to
   confirm bob is up, before wiring anything.

## exec allowlist (important — why exec gets denied)

`alice exec` is **default-deny**. The operator must pre-bless exact regex rules
in `~/.anb/alice/exec-allowlist.rules`. As a non-TTY agent, an unmatched command
is **hard-denied with no prompt** — you can't widen it yourself. So if `exec`
fails with an allowlist error: **stop retrying, tell the human which exact
command + env keys you need**, and ask them to add a rule. `--show-match-string`
prints the canonical string a rule must match (run it to give the human the
exact pattern).

## Common mistakes

- Calling `alice get --reveal` to "read the value" — it's TTY-only, will fail,
  and you don't need the value; use `exec`/`write` with the placeholder.
- Printing a resolved secret to stdout/logs — never; keep it in the placeholder.
- Hardcoding a secret because `exec` was denied — instead surface the allowlist
  rule the operator needs to add.
- Assuming `template` works — it's human-only; use `write`.

## Setup state (when nothing works)

If every command errors, alice may not be enrolled or bob may be down. Run
`alice status`. Enrollment, `bob serve`, and storing secrets (`alice set`) are
operator/human tasks — ask the human; see the AnB README.
