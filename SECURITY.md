# Security policy

One Eye is a security tool, so a bug in it can hurt the people using it. Thank you for reporting one.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Use GitHub's
**Security → Report a vulnerability** (private advisory) on this repository instead, with:

- what an attacker can do, and what they need first (e.g. "a normal-user program can make One Eye, running as admin, ...")
- steps to reproduce, and the One Eye version (Settings / sidebar)

We aim to reply within a week. This is a student project maintained in spare time, so there is no bug bounty.

## Design rules we hold ourselves to

- One Eye never acts on its own: every change (quarantine, end process, firewall rule) is the user's click, and is logged.
- The AI assistant gets a redacted snapshot and returns text only; it has no access to any action code (tested).
- Files in user-writable folders are treated as untrusted when One Eye runs as admin: no pickle, an admin-only ClamAV path,
  and restore writes only inside the user's own folder.
- Commands are run as argument lists, never through a shell; IPs and paths are validated first.
- Threat feeds are downloaded and matched locally; nothing about the PC is sent to them.
