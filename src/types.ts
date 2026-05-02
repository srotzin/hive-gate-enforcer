/**
 * Types for hive-gate-enforcer — Gate Enforcement (HiveAttest C19).
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

/** A minimal HivePassport credential (identity attestation). */
export interface HivePassportCredential {
  /** Agent DID. */
  agent_did: string;
  /** Base64url raw 32-byte public key. */
  public_key_b64u: string;
  /** ISO-8601 UTC expiry. */
  expires_at: string;
  /** Ed25519 signature over JCS body (excluding this field). */
  signature: string;
  /** Base64url raw 32-byte authority public key that signed this credential. */
  authority_key_id: string;
}

/** A pre-action manifest presented to the gate (minimal representation). */
export interface GateManifest {
  manifest_id: string;
  agent_did: string;
  intended_op: string;
  target_resource: string;
  declared_inputs_hash: string;
  issued_at: string;
  valid_until: string;
  /** Cargo type IDs declared present in this payload. */
  declared_cargo: string[];
  /** Ed25519 signature over JCS body (excluding this field). */
  signature: string;
  key_id: string;
}

/** Gate policy: what cargo types are allowed/required for this destination. */
export interface GatePolicy {
  /** Destination resource pattern (exact match or glob). */
  resource: string;
  /** Cargo types that MUST be declared present. */
  required_cargo?: string[];
  /** Cargo types that MUST NOT be present. */
  forbidden_cargo?: string[];
  /** Maximum allowed manifest age in seconds (from issued_at). */
  max_manifest_age_seconds?: number;
}

/** Missing prerequisite codes returned in the 401 header. */
export type MissingPrereqCode =
  | "MISSING_PASSPORT"
  | "EXPIRED_PASSPORT"
  | "INVALID_PASSPORT_SIGNATURE"
  | "MISSING_MANIFEST"
  | "EXPIRED_MANIFEST"
  | "INVALID_MANIFEST_SIGNATURE"
  | "CARGO_MISMATCH"
  | "FORBIDDEN_CARGO"
  | "DID_MISMATCH";

/** Structured WWW-Authenticate-style header on 401. */
export interface GateChallenge {
  scheme: "HiveAttest";
  realm: string;
  missing: MissingPrereqCode[];
  /** Human-readable descriptions per missing item. */
  descriptions: Record<MissingPrereqCode, string>;
}

/** Gate decision. */
export interface GateDecision {
  allowed: boolean;
  /** Present when allowed=false. */
  challenge?: GateChallenge;
  /** Present when allowed=true. */
  decisionId?: string;
  /** Hex SHA-256 of the canonical gate decision body (audit fingerprint). */
  fingerprint?: string;
}
