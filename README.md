# hive-gate-enforcer

**HiveAttest Claim C19 — Gate Enforcement**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](package.json)
[![Patent](https://img.shields.io/badge/USPTO-64%2F055%2C601-gold.svg)](https://www.uspto.gov/)

A TypeScript perimeter-gate library that cryptographically enforces the
**pre-action manifest** protocol of HiveAttest. Before any agent may
execute a declared operation it must present:

1. A valid **HivePassport** — identity credential issued by a trusted authority, not expired, Ed25519 signature valid
2. A valid **pre-action Manifest** — signed by the agent's own key, within TTL, DID matching the passport
3. Compliance with the applicable **cargo policy** — required cargo types declared, forbidden types absent

On failure the gate returns a structured `GateChallenge` (analogous to
`WWW-Authenticate`) listing every `MissingPrereqCode`. On success it
returns an allowed `GateDecision` with a cryptographic fingerprint that
provides an audit trail of the gate evaluation.

---

## Install

```bash
npm install @hivecivilization/hive-gate-enforcer
```

---

## Quick Start

```typescript
import { GateEnforcer, GateCredentialIssuer } from "@hivecivilization/hive-gate-enforcer";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

// Required for synchronous signing in tests / Node environments
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// Authority issues passports; agents sign their own manifests
const authorityKey = ed.utils.randomPrivateKey();
const issuer = new GateCredentialIssuer(authorityKey);

// Agent key pair
const agentKey = ed.utils.randomPrivateKey();
const agentPubB64u = btoa(String.fromCharCode(...ed.getPublicKey(agentKey)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

// Issue credential & manifest
const passport = issuer.issuePassport({
  agentDid: "did:hive:agent-abc123",
  agentPubKeyB64u: agentPubB64u,
});
const manifest = issuer.issueManifest({
  agentDid: "did:hive:agent-abc123",
  agentPrivKey: agentKey,
  targetResource: "https://api.example.com/v1/infer",
  declaredCargo: ["pii", "logs"],
});

// Gate enforcer with cargo policy
const gate = new GateEnforcer({
  authorityPubKeyB64u: issuer.publicKeyB64u,
  realm: "prod-inference-gate",
  policies: [
    {
      resource: "https://api.example.com/v1/infer",
      required_cargo: ["pii"],
      forbidden_cargo: ["classified"],
    },
  ],
});

const decision = await gate.evaluate({ passport, manifest });

if (!decision.allowed) {
  const header = GateEnforcer.formatChallenge(decision.challenge!);
  // → 'HiveAttest realm="prod-inference-gate" missing="..."'
  throw new Error(`Gate denied: ${header}`);
}

console.log("Allowed. Fingerprint:", decision.fingerprint);
```

---

## API

### `new GateEnforcer(opts)`

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `authorityPubKeyB64u` | `string` | Yes | Base64url-encoded 32-byte Ed25519 public key of the passport-issuing authority |
| `realm` | `string` | No | WWW-Authenticate realm (default: `"hive-gate"`) |
| `policies` | `GatePolicy[]` | No | Cargo policies to enforce (default: `[]`) |

### `gate.evaluate(opts): Promise<GateDecision>`

Evaluates a gate request. Both `passport` and `manifest` accept `null`
(absence produces the appropriate `MissingPrereqCode`).

Returns `GateDecision`:
- `allowed: true` — includes `decisionId` (UUID) and `fingerprint` (SHA-256 hex)
- `allowed: false` — includes `challenge: GateChallenge` with `missing[]` and `descriptions`

### `GateEnforcer.formatChallenge(challenge): string`

Formats a `GateChallenge` as a `WWW-Authenticate`-style header value:

```
HiveAttest realm="<realm>" missing="<code1> <code2> ..."
```

### `GateCredentialIssuer`

Development/test helper. Do not use in production credential pipelines.

```typescript
const issuer = new GateCredentialIssuer(privateKey32Bytes);
issuer.publicKeyB64u  // authority public key (for GateEnforcer constructor)
issuer.issuePassport({ agentDid, agentPubKeyB64u, ttlSeconds?, nowMs? })
issuer.issueManifest({ agentDid, agentPrivKey, targetResource?, declaredCargo?, ttlSeconds?, nowMs? })
```

---

## Missing Prerequisite Codes

| Code | Meaning |
|------|---------|
| `MISSING_PASSPORT` | No passport credential presented |
| `EXPIRED_PASSPORT` | Passport `expires_at` is in the past |
| `INVALID_PASSPORT_SIGNATURE` | Ed25519 signature over passport body fails |
| `MISSING_MANIFEST` | No pre-action manifest presented |
| `EXPIRED_MANIFEST` | Manifest `valid_until` is in the past |
| `INVALID_MANIFEST_SIGNATURE` | Ed25519 signature over manifest body fails |
| `DID_MISMATCH` | Passport and manifest `agent_did` disagree |
| `CARGO_MISMATCH` | A required cargo type is absent from declared cargo |
| `FORBIDDEN_CARGO` | A forbidden cargo type is present in declared cargo |

---

## Gate Policy

```typescript
interface GatePolicy {
  resource: string;          // exact resource URL or "*" for wildcard
  required_cargo?: string[]; // cargo types that MUST be declared
  forbidden_cargo?: string[]; // cargo types that MUST NOT be declared
  max_manifest_age_seconds?: number; // reserved for future use
}
```

Policies are matched by exact `resource` URL or `"*"` wildcard. Multiple
policies may apply to a single request; all are evaluated.

---

## Cargo Policy Patterns

**Require PII declaration:**
```typescript
{ resource: "https://api.example.com/analyze", required_cargo: ["pii"] }
```

**Block classified data everywhere:**
```typescript
{ resource: "*", forbidden_cargo: ["classified", "top-secret"] }
```

---

## Cryptographic Details

- **Passport signing:** Ed25519 over RFC 8785 JCS-canonicalized body
  `{ agent_did, authority_key_id, expires_at, public_key_b64u }`
- **Manifest signing:** Ed25519 over JCS-canonicalized body
  `{ agent_did, declared_cargo, declared_inputs_hash, intended_op, issued_at, key_id, manifest_id, target_resource, valid_until }`
- **Decision fingerprint:** SHA-256 of JCS-canonicalized
  `{ decision_id, allowed, manifest_id, agent_did, evaluated_at }`
- All keys and signatures encoded as base64url (no padding)
- Crypto provided by `@noble/ed25519` and `@noble/hashes` — audited, zero-dependency

---

## Development

```bash
npm run typecheck   # tsc --noEmit
npm run build       # tsc
npm run test        # vitest run
npm run test:watch  # vitest watch
npm run test:coverage # vitest run --coverage
```

---

## Patent

This software is a reference implementation of HiveAttest.

**USPTO Provisional Application No. 64/055,601**
Inventor: Stephen A. Rotzin, Walnut Creek, CA

---

## License

Apache-2.0 — see [LICENSE](LICENSE)
Copyright 2026 Stephen A. Rotzin
