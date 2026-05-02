/**
 * hive-gate-enforcer — Public API surface.
 *
 * Implements HiveAttest Claim C19: Gate Enforcement.
 * Perimeter gate requiring a valid HivePassport + pre-action manifest
 * before any agent is permitted to perform a declared operation.
 *
 * @packageDocumentation
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

export { GateEnforcer, GateCredentialIssuer } from "./gate.js";
export type {
  GateChallenge,
  GateDecision,
  GateManifest,
  GatePolicy,
  HivePassportCredential,
  MissingPrereqCode,
} from "./types.js";
