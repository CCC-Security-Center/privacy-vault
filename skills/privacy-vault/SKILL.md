---
name: privacy-vault
description: Pseudonymize identities in structured engagement data (IPs, hostnames, usernames, emails, domains, paths, registered credentials) before it is written to a shared file or sent to a third party, and gate commands that need the real values. Use for log exports, tool output and other structured case data that will leave the local machine or enter a shared report. Not a protection for prose documents or file content, and not a boundary against the model provider.
---

# privacy-vault

`privacy_vault.py` is an offline CLI (Python 3.8+, `cryptography`). It replaces sensitive values
with stable placeholders (`IP_PRIVATE_001`, `USER_003`), keeps the real values encrypted in a
local vault, and only puts real values back into a command once a policy check has allowed it.

Locate the script: it sits at the repository root, two levels above this file
(`../../privacy_vault.py`). Use its absolute path in commands.

## What it can and cannot do

- **Can:** reliably tokenize identities in structured exports (CSV/TSV/JSON/JSON-lines with labeled
  columns or keys), shaped values (IPs, emails, URLs, domains, paths, MACs) anywhere, and anything registered.
- **Cannot:** protect prose. In tickets, emails, chats and documents, names are caught only if the session
  already learned them from a labeled field. Phone numbers, addresses and unregistered IDs pass through,
  and the content itself (what happened, to whom) is never hidden.
- **Is not** a boundary against the model provider. What you read reaches the provider; sanitizing first only
  reduces it. If a file may not leave the machine, do not read it at all. Tell the user instead of sanitizing
  it and reading the result.

## When to use it

- **Before** pasting log excerpts, tool output or structured case files into anything that leaves
  the machine: a ticket, an email, a shared report, a third-party service.
- **When writing** a report or note into a shared or synced folder.
- **When you hold a credential, hash or ID** that must never appear in output: register it first.

## How

```sh
P=/abs/path/to/privacy_vault.py
python3 $P --session <case> init --target <in-scope host/CIDR> ...   # once per case
python3 $P --session <case> register CRED -  < secrets.txt            # one per line; also HASH, SERIAL, STUDENT_ID
some-tool | python3 $P --session <case> sanitize > safe.txt           # tokenize output
python3 $P --session <case> sanitize-file IN OUT                   # FILES: use this; exit 3 = refused, 2 = review leftovers
python3 $P --session <case> sanitize-file --ndjson IN OUT          # JSON-lines files (one object per line)
python3 $P audit OUT                                               # leftover candidates (counts + line numbers only)
python3 $P --session <case> check "nmap -sV IP_PRIVATE_001"           # ALLOW / BLOCK: reason
python3 $P --session <case> rehydrate "nmap -sV IP_PRIVATE_001"       # prints the real, quoted command
```

`--session` must come **before** the subcommand (`init --session x` is rejected).

## Rules

- **Files: always `sanitize-file`, never `sanitize < file > out`.** Read OUT only after exit 0. On exit 2,
  register the real leftovers and re-run. On exit 3, nothing was written: fix the input.
  For a JSON-lines export (one JSON object per line) add `--ndjson`, or escaped paths can break lines.
- Work from placeholders. Rehydrate only through `rehydrate`, never by calling `reveal` to print values.
- A `BLOCK` from `check` is a decision, not an error to work around. Report it to the user.
- **Sanitize is heuristic.** It doesn't catch personal names in plain prose, and it only protects
  credentials you have registered. Before anything leaves, also search the output for the case's
  known identifiers (organization, hosts, users, first names, ticket IDs).
- Never copy the vault directory (`~/.privacy-vault/`, or `PRIVACY_VAULT_DIR`) into a repository or
  shared folder. It holds the key next to the encrypted values.
