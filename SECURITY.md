# Security Policy — hive-gate-enforcer

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Please report security vulnerabilities **privately** to:

- **Email:** srotzin@me.com
- **Subject line:** `[SECURITY] hive-gate-enforcer <brief description>`

Do **not** open a public GitHub issue for security vulnerabilities.

**Response SLA:**
- Acknowledgement within 48 hours
- Triage and severity assessment within 7 days
- Patch or mitigation plan within 30 days for critical/high issues

## Scope

This library enforces perimeter gate decisions using Ed25519 signatures
(via `@noble/ed25519`) and SHA-256 fingerprinting. In scope for security
reports:

- Signature bypass or forgery
- Timing attacks on signature verification
- Credential replay attacks
- Policy bypass (cargo / DID mismatch)
- Dependency vulnerabilities in `@noble/ed25519`, `@noble/hashes`

## Out of Scope

- Denial-of-service via crafted inputs (treated as operational concern)
- Vulnerabilities in downstream consumers of this library

## Cryptographic Notice

This library uses only constant-time, audited cryptographic primitives
from the `@noble` family. Do not replace these with custom implementations.
