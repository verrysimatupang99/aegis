# Security policy

## Scope

Aegis is a defensive security tool. It is intentionally narrow: scanning,
auditing, and remediation guidance. It is not a general-purpose agent and it
will refuse to produce offensive tooling regardless of phrasing.

## Reporting a vulnerability

Email security disclosures to the maintainer (replace with your address before
publishing). Do not file public issues for unpatched bugs.

We will:

- Acknowledge within 72 hours.
- Provide an initial assessment within 7 days.
- Keep you in the loop until a fix ships.

## Scope of supported research

In-scope:

- Bypasses of the Mythos charter (e.g., a path that lets a tool act without
  going through `policy.check_action`).
- Secret-detection regressions where a real credential is echoed unredacted.
- Index or journal corruption from a crafted input file.
- MCP request that crashes the stdio loop.

Out of scope:

- Findings about the original arctryx loader (that file is a deliberate
  fixture; the project removed it from active use).
- "The LLM said something I disagree with" - that is a model issue, not an
  Aegis issue.

## Hardening defaults

- Aegis loads its constitution as immutable (`@dataclass(frozen=True)`).
- All outbound network access is denied unless the host is on the charter
  allowlist or `--allow-exfil` is passed.
- Detected secrets are SHA-256 fingerprinted before they reach the index,
  journal, or any LLM context.
- Destructive actions require `--i-mean-it`.
