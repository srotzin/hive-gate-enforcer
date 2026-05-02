# Specification — hive-gate-enforcer

**HiveAttest Claim C19: Gate Enforcement**
USPTO Provisional Application No. 64/055,601
Inventor: Stephen A. Rotzin

---

## 1. Purpose

A perimeter gate enforces the HiveAttest pre-action manifest protocol.
No agent may initiate a declared operation without presenting a valid
HivePassport identity credential AND a cryptographically-signed pre-action
manifest that matches the passport and satisfies all cargo policies.

---

## 2. Prerequisites

A gate evaluation `ALLOW`s only when ALL of the following conditions hold:

### 2.1 Passport Conditions

| Condition | Check |
|-----------|-------|
| P-1 | A `HivePassportCredential` is present (not null) |
| P-2 | `passport.expires_at > now` |
| P-3 | Ed25519 signature over JCS body verifies against `authorityPubKeyB64u` |

### 2.2 Manifest Conditions

| Condition | Check |
|-----------|-------|
| M-1 | A `GateManifest` is present (not null) |
| M-2 | `manifest.valid_until > now` |
| M-3 | `manifest.agent_did === passport.agent_did` |
| M-4 | Ed25519 signature over JCS body verifies against `passport.public_key_b64u` |

### 2.3 Cargo Conditions

For each `GatePolicy` where `policy.resource === manifest.target_resource`
or `policy.resource === "*"`:

| Condition | Check |
|-----------|-------|
| C-1 | All `policy.required_cargo` types present in `manifest.declared_cargo` |
| C-2 | No `policy.forbidden_cargo` types present in `manifest.declared_cargo` |

---

## 3. Missing Prerequisite Codes

When one or more conditions fail, the gate returns `allowed: false` with a
`GateChallenge` listing every `MissingPrereqCode` from the set:

```
MISSING_PASSPORT
EXPIRED_PASSPORT
INVALID_PASSPORT_SIGNATURE
MISSING_MANIFEST
EXPIRED_MANIFEST
INVALID_MANIFEST_SIGNATURE
CARGO_MISMATCH
FORBIDDEN_CARGO
DID_MISMATCH
```

All applicable failures are accumulated — a single evaluation may return
multiple codes.

---

## 4. Gate Challenge Format

On deny, the challenge serialises as a `WWW-Authenticate`-style header:

```
HiveAttest realm="<realm>" missing="<code1> <code2> ..."
```

This is produced by `GateEnforcer.formatChallenge(challenge)`.

---

## 5. Allowed Decision

On allow, the gate returns:

```json
{
  "allowed": true,
  "decisionId": "<uuid-v4>",
  "fingerprint": "<sha256hex(canonicalize(decisionBody))>"
}
```

Where `decisionBody` is:

```json
{
  "decision_id": "<decisionId>",
  "allowed": true,
  "manifest_id": "<manifest.manifest_id>",
  "agent_did": "<manifest.agent_did>",
  "evaluated_at": "<ISO-8601 UTC>"
}
```

---

## 6. Signing Conventions

### Passport body (canonicalized before signing by authority)
```json
{
  "agent_did": "...",
  "authority_key_id": "...",
  "expires_at": "...",
  "public_key_b64u": "..."
}
```

### Manifest body (canonicalized before signing by agent)
```json
{
  "agent_did": "...",
  "declared_cargo": [...],
  "declared_inputs_hash": "...",
  "intended_op": "...",
  "issued_at": "...",
  "key_id": "...",
  "manifest_id": "...",
  "target_resource": "...",
  "valid_until": "..."
}
```

All canonicalization uses RFC 8785 JCS (keys sorted UTF-16, no undefined values).
All keys and signatures are base64url-encoded with no padding.

---

## 7. Cargo Policy Semantics

- `required_cargo`: all listed types MUST appear in `manifest.declared_cargo`
- `forbidden_cargo`: none of the listed types may appear in `manifest.declared_cargo`
- `resource: "*"` matches any `manifest.target_resource`
- Multiple policies may match a single request; all are evaluated
- `CARGO_MISMATCH` and `FORBIDDEN_CARGO` are deduplicated across policy violations

---

## 8. Reference Implementation

- Language: TypeScript (strict mode), Node 20+
- Crypto: `@noble/ed25519 ^2.2.3`, `@noble/hashes ^1.7.2`
- Tests: vitest, ≥51 tests, ≥96% statement coverage, ≥88% branch coverage
