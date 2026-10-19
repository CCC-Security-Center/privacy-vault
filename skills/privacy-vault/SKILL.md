---
name: privacy-vault
description: Tokenize sensitive engagement data (IPs, hostnames, usernames, emails, domains, paths, registered credentials) before it is shown to a model, written to a shared file, or sent to a third party, and gate commands that need the real values. Use whenever log excerpts, tool output or case data would leave the local machine or enter a shared report.
---

# privacy-vault

`privacy_vault.py` is an offline CLI (Python 3.8+, `cryptography`). It replaces sensitive values
with stable placeholders (`IP_PRIVATE_001`, `USER_003`), keeps the real values encrypted in a
local vault, and only puts real values back into a command once a policy check has allowed it.

Locate the script: it sits at the repository root, two levels above this file
(`../../privacy_vault.py`). Use its absolute path in commands.

## When to use it

- **Before** pasting log excerpts, tool output or case files into anything that leaves the
  machine: another AI service, a ticket, an email, a shared report.
- **When writing** a report or note into a shared or synced folder.
- **When you hold a credential, hash or ID** that must never appear in output: register it first.

## How

```sh
P=/abs/path/to/privacy_vault.py
python3 $P --session <case> init --target <in-scope host/CIDR> ...   # once per case
python3 $P --session <case> register CRED -  < secrets.txt            # one per line; also HASH, SERIAL, STUDENT_ID
some-tool | python3 $P --session <case> sanitize > safe.txt           # tokenize output
python3 $P --session <case> sanitize-file IN OUT                   # FILES: use this; exit 3 = refused, 2 = review leftovers
python3 $P audit OUT                                               # leftover candidates (counts + line numbers only)
python3 $P --session <case> check "nmap -sV IP_PRIVATE_001"           # ALLOW / BLOCK: reason
python3 $P --session <case> rehydrate "nmap -sV IP_PRIVATE_001"       # prints the real, quoted command
```

`--session` must come **before** the subcommand (`init --session x` is rejected).

## Rules

- **Files: always `sanitize-file`, never `sanitize < file > out`.** Read OUT only after exit 0. On exit 2,
  register the real leftovers and re-run. On exit 3, nothing was written: fix the input.
- Work from placeholders. Rehydrate only through `rehydrate`, never by calling `reveal` to print values.
- A `BLOCK` from `check` is a decision, not an error to work around. Report it to the user.
- **Sanitize is heuristic.** It doesn't catch personal names in plain prose, and it only protects
  credentials you have registered. Before anything leaves, also search the output for the case's
  known identifiers (organization, hosts, users, first names, ticket IDs).
- Never copy the vault directory (`~/.privacy-vault/`, or `PRIVACY_VAULT_DIR`) into a repository or
  shared folder. It holds the key next to the encrypted values.
