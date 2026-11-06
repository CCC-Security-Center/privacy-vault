# privacy-vault

A privacy vault and command gateway for offensive-security and IR work. It pseudonymises the
identities in **structured** engagement data (internal IPs, hostnames, usernames, emails, registered
credentials) before that data goes into a shared report, a log, a ticket or a third-party tool, and it
checks commands before real values are put back into them.

## What it is, and what it is not

**It is good at:**

- **Structured exports:** sign-in logs, device timelines, SIEM/EDR query results and other CSV, TSV,
  JSON or JSON-lines data. Column and key names say which value is a user, a host or an address, so
  those values are tokenised reliably.
- **Values with a recognisable shape** anywhere in text: IPs, MACs, emails, URLs, domains, paths,
  `DOMAIN\user`, LDAP DNs.
- **Values you register:** credentials, hashes, serials and IDs, including encoded copies of them.
- **Gating outbound commands:** a protected value is only released to an in-scope target.

**It is not:**

- **Protection for prose or for content.** Tickets, emails, chat logs, case notes and documents
  come out pseudonymised at best. A person's name in free text is caught only when the same session
  has already learned it from a labelled field. Phone numbers, street addresses and unregistered
  IDs pass through. Nothing hides *what* a file says, and the context alone often identifies the
  person.
- **A boundary against your AI provider.** Whatever reaches a model's context reaches that
  provider. The vault reduces what gets there only when you sanitise before the model reads.
  Unsanitised tool output, search results and pasted text go through as they are. If data may not
  leave the machine, keep it away from hosted models. Sanitising does not make it safe to send.
- **Complete, even for logs.** Free-text fields inside structured data (email subjects, command
  lines, URLs, alert descriptions) are weak spots. So are export formats the rules haven't seen yet.

- **`protect` / `sanitize`** swap sensitive values for stable placeholders
  (`IP_PRIVATE_001`, `USER_003`, `HOST_INTERNAL_007`). Within a session the same value always
  gets the same placeholder, so a report written with placeholders stays consistent and diffable.
- **`register`** protects values that no pattern can reliably find: credentials, hashes,
  serials and student IDs. Base64, hex, URL-encoded, JSON-escaped and PowerShell
  `-EncodedCommand` copies of a registered value are masked too.
- **`check` / `rehydrate`** decide whether a command written with placeholders may run with
  the real values. They block by default. A protected value is released only to a destination
  in the engagement's target scope, in an argument position that no shell, interpreter or
  remote shell re-reads. Print sinks, request bodies, proxies and DNS-label exfiltration are
  refused.

Single file, Python 3.8+, one dependency (`cryptography`).

## Quick start

```sh
pip install cryptography            # or: apt install python3-cryptography
python3 privacy_vault.py selftest   # ~300 checks

python3 privacy_vault.py init --target example.org --target 10.99.17.0/24
python3 privacy_vault.py register CRED -  < creds.txt        # one per line, kept out of shell history
some-tool | python3 privacy_vault.py sanitize > safe.txt
python3 privacy_vault.py sanitize-file export.csv export.sanitized.csv  # files: refuses empty output, audits result
python3 privacy_vault.py sanitize-file --ndjson events.json events.sanitized.json  # JSON-lines: lines stay valid JSON
python3 privacy_vault.py audit export.sanitized.csv                     # leftover candidates: counts + line numbers only
python3 privacy_vault.py check     "nmap -sV IP_PRIVATE_001"   # ALLOW / BLOCK: reason
python3 privacy_vault.py rehydrate "nmap -sV IP_PRIVATE_001"   # prints the real, quoted command
```

`--session NAME` (before the subcommand) keeps engagements apart.

## Using it with an AI agent

`skills/privacy-vault/SKILL.md` tells an agent when and how to use the tool. It uses the open
`SKILL.md` format, so it works in several agents:

- **Claude Code:** `ln -s "$PWD/skills/privacy-vault" ~/.claude/skills/`
- **OpenAI Codex:** `ln -s "$PWD/skills/privacy-vault" ~/.agents/skills/`
- **Anything else:** point the agent at the file.

The skill finds `privacy_vault.py` two directories above itself, so keep the repository intact and
symlink the folder rather than copying it.

## What it detects

URLs (including schemeless `host/path`), emails, IPv4/IPv6 (including tcpdump `ip.port`, SNMP
OID indexes and PTR names), MACs, internal hostnames, domains, file paths, LDAP DNs, Windows
default and machine-account names, and names identified only by their field
(`"AccountName": "jdoe"`, `Account Name:  jdoe`, `user=jdoe`, CSV/TSV/markdown table columns,
nested JSON and Python reprs).

## Limits (read these)

- **Detection uses heuristics.** It is tuned to leak less, not to be pretty, and it will
  still miss things. Review anything that matters before you share it.
- **Use `sanitize-file` for files.** It refuses to write an empty or truncated result (a silent empty output once
  passed a "nothing left" check), and audits what it wrote: exit code 2 means leftover candidates, such as
  uppercase server names in an unlabelled column, which no rule tokenizes automatically. Review them and
  `register HOST_INTERNAL -` the real ones. The audit prints counts and line numbers only, never values.
  For JSON-lines exports (one JSON object per line, as SIEM and EDR exports often are) add `--ndjson`:
  each key and string value is tokenized on its own and the line is re-serialised, so it still parses.
  The plain text pass can break escaped Windows paths and leave lines that no longer parse.
- **Prose is not covered.** See "What it is not" above. For narrative files, sanitising is a
  courtesy, not a control.
- **Credentials are protected only once you register them.** Nothing tries to guess what a
  password looks like.
- **The key is stored in the vault file.** Each session file
  (`~/.privacy-vault/<session>.json`, mode 0600) holds the Fernet key next to the encrypted
  values. The encryption stops casual greps and accidental copies. The file permission is
  what actually protects it. Keep the vault outside git repos and synced folders.
- **The gateway does not sandbox anything.** It checks a command string before you run it,
  and it can only reason about tools it has a spec for (`_TOOL_SPECS`). Any other tool may
  receive a protected value only when that value is itself a target.

## Configuration

| Variable | Effect |
|---|---|
| `PRIVACY_VAULT_DIR` | Vault directory (default `~/.privacy-vault`) |
| `PRIVACY_VAULT_CATEGORIES` | Comma list narrowing auto-detection. If it is malformed or empty, the full default set is used. |

## Credits

Some designs here were reimplemented from other projects. No code was copied from them.

- **Dark-Moon** (GPL-3.0): the vault and gateway pattern, register-only credentials, and
  configuration that falls back to protecting more.
- **LogTotal Sanitizer** by SOC Prime (Apache-2.0): field-name redaction, IPv6/MAC/PTR/OID
  handling, and Windows default-name rules.
- **DFIR-IRIS** (LGPL-3.0): masking encoded copies of registered secrets.

Inline tags `[DM]` `[LT]` `[DI]` mark where each idea is used. `[RT]` marks original work.

## License

MIT. See [LICENSE](LICENSE).
