# Changelog — hive-gate-enforcer

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-05-02

### Added
- `GateEnforcer.evaluate()` — async gate decision engine:
  - Validates HivePassport credential (existence, expiry, Ed25519 signature)
  - Validates pre-action Attestation Manifest (existence, expiry, DID match, Ed25519 signature)
  - Enforces cargo taxonomy policies (required cargo, forbidden cargo)
  - Returns structured `GateDecision` with cryptographic fingerprint on allow
  - Returns structured `GateChallenge` listing all `MissingPrereqCode` values on deny
- `GateEnforcer.formatChallenge()` — formats `GateChallenge` as a `WWW-Authenticate`-style header value
- `GateCredentialIssuer` — test/development helper for issuing passports and manifests:
  - `issuePassport()` — issues an Ed25519-signed `HivePassportCredential`
  - `issueManifest()` — issues an Ed25519-signed `GateManifest`
- Full TypeScript types: `HivePassportCredential`, `GateManifest`, `GatePolicy`, `GateChallenge`, `GateDecision`, `MissingPrereqCode`
- 51 vitest tests, 96.9% statement coverage, 88% branch coverage
- CI via GitHub Actions Node 20/22 matrix

### Patent Reference
- Implements HiveAttest Claim C19 (Gate Enforcement)
- USPTO Provisional Application No. 64/055,601
- Inventor: Stephen A. Rotzin
