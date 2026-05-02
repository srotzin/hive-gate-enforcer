/**
 * hive-gate-enforcer — Gate Enforcement (HiveAttest Claim C19).
 *
 * Perimeter gate that requires:
 *   1. Valid HivePassport (identity credential, not expired, signature OK)
 *   2. Valid pre-action manifest (signature OK, within TTL, DID matches passport)
 *   3. Cargo-taxonomy match (no forbidden cargo, required cargo present)
 *
 * On failure: returns a structured GateChallenge (WWW-Authenticate-style)
 * listing all missing prerequisites.
 *
 * Gate Decision is itself cryptographically fingerprinted (recursive attestation).
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import type {
  GateChallenge,
  GateDecision,
  GateManifest,
  GatePolicy,
  HivePassportCredential,
  MissingPrereqCode,
} from "./types.js";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function b64uDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function b64uEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function sha256Hex(data: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(data)));
}

function canonicalize(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return JSON.stringify(v)!;
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.filter((k) => obj[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
  }
  throw new TypeError(`canonicalize: ${typeof v}`);
}

function randomUUID(): string {
  const c = (globalThis as Record<string, unknown>).crypto as { randomUUID?: () => string } | undefined;
  if (c?.randomUUID) return c.randomUUID();
  const b = ed.utils.randomPrivateKey().slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// ---------------------------------------------------------------------------
// Passport signing helpers
// ---------------------------------------------------------------------------

function passportSigningBody(p: HivePassportCredential): Uint8Array {
  const body = {
    agent_did: p.agent_did,
    authority_key_id: p.authority_key_id,
    expires_at: p.expires_at,
    public_key_b64u: p.public_key_b64u,
  };
  return new TextEncoder().encode(canonicalize(body));
}

function manifestSigningBody(m: GateManifest): Uint8Array {
  const body = {
    agent_did: m.agent_did,
    declared_cargo: m.declared_cargo,
    declared_inputs_hash: m.declared_inputs_hash,
    intended_op: m.intended_op,
    issued_at: m.issued_at,
    key_id: m.key_id,
    manifest_id: m.manifest_id,
    target_resource: m.target_resource,
    valid_until: m.valid_until,
  };
  return new TextEncoder().encode(canonicalize(body));
}

// ---------------------------------------------------------------------------
// GateCredentialIssuer — for creating test passports and manifests
// ---------------------------------------------------------------------------

export class GateCredentialIssuer {
  private readonly privKey: Uint8Array;
  private readonly pubKeyB64u: string;

  constructor(privKey: Uint8Array) {
    if (privKey.length !== 32) throw new Error("Expected 32-byte key");
    this.privKey = privKey;
    this.pubKeyB64u = b64uEncode(ed.getPublicKey(privKey));
  }

  get publicKeyB64u(): string { return this.pubKeyB64u; }

  issuePassport(opts: {
    agentDid: string;
    agentPubKeyB64u: string;
    ttlSeconds?: number;
    nowMs?: number;
  }): HivePassportCredential {
    const nowMs = opts.nowMs ?? Date.now();
    const ttl = opts.ttlSeconds ?? 3600;
    const expiresAt = new Date(nowMs + ttl * 1000).toISOString();

    const partial: Omit<HivePassportCredential, "signature"> = {
      agent_did: opts.agentDid,
      public_key_b64u: opts.agentPubKeyB64u,
      expires_at: expiresAt,
      authority_key_id: this.pubKeyB64u,
    };

    const bodyBytes = passportSigningBody(partial as HivePassportCredential);
    const sig = ed.sign(bodyBytes, this.privKey);
    return { ...partial, signature: b64uEncode(sig) };
  }

  issueManifest(opts: {
    agentDid: string;
    agentPrivKey: Uint8Array;
    intendedOp?: string;
    targetResource?: string;
    declaredCargo?: string[];
    ttlSeconds?: number;
    nowMs?: number;
  }): GateManifest {
    const nowMs = opts.nowMs ?? Date.now();
    const ttl = opts.ttlSeconds ?? 300;
    const agentPubB64u = b64uEncode(ed.getPublicKey(opts.agentPrivKey));

    const partial: Omit<GateManifest, "signature"> = {
      manifest_id: randomUUID(),
      agent_did: opts.agentDid,
      intended_op: opts.intendedOp ?? "tool_invocation",
      target_resource: opts.targetResource ?? "https://api.example.com",
      declared_inputs_hash: sha256Hex("{}"),
      issued_at: new Date(nowMs).toISOString(),
      valid_until: new Date(nowMs + ttl * 1000).toISOString(),
      declared_cargo: opts.declaredCargo ?? [],
      key_id: agentPubB64u,
    };

    const bodyBytes = manifestSigningBody(partial as GateManifest);
    const sig = ed.sign(bodyBytes, opts.agentPrivKey);
    return { ...partial, signature: b64uEncode(sig) };
  }
}

// ---------------------------------------------------------------------------
// GateEnforcer
// ---------------------------------------------------------------------------

export class GateEnforcer {
  private readonly authorityPubKeyB64u: string;
  private readonly realm: string;
  private readonly policies: GatePolicy[];

  constructor(opts: {
    authorityPubKeyB64u: string;
    realm?: string;
    policies?: GatePolicy[];
  }) {
    this.authorityPubKeyB64u = opts.authorityPubKeyB64u;
    this.realm = opts.realm ?? "hive-gate";
    this.policies = opts.policies ?? [];
  }

  /**
   * Evaluate a gate request.
   *
   * Returns an allowed=true GateDecision with fingerprint, or
   * allowed=false with a structured GateChallenge listing all missing prerequisites.
   */
  async evaluate(opts: {
    passport: HivePassportCredential | null;
    manifest: GateManifest | null;
    nowMs?: number;
  }): Promise<GateDecision> {
    const nowMs = opts.nowMs ?? Date.now();
    const missing: MissingPrereqCode[] = [];
    const descriptions: Partial<Record<MissingPrereqCode, string>> = {};

    // -----------------------------------------------------------------------
    // 1. Passport checks
    // -----------------------------------------------------------------------
    if (!opts.passport) {
      missing.push("MISSING_PASSPORT");
      descriptions["MISSING_PASSPORT"] = "A valid HivePassport credential is required";
    } else {
      const p = opts.passport;

      // Expiry
      if (new Date(p.expires_at).getTime() < nowMs) {
        missing.push("EXPIRED_PASSPORT");
        descriptions["EXPIRED_PASSPORT"] = `Passport expired at ${p.expires_at}`;
      }

      // Signature
      let passportSigOk = false;
      try {
        const pubBytes = b64uDecode(this.authorityPubKeyB64u);
        const sigBytes = b64uDecode(p.signature);
        const bodyBytes = passportSigningBody(p);
        passportSigOk = ed.verify(sigBytes, bodyBytes, pubBytes);
      } catch {
        passportSigOk = false;
      }
      if (!passportSigOk) {
        missing.push("INVALID_PASSPORT_SIGNATURE");
        descriptions["INVALID_PASSPORT_SIGNATURE"] = "Passport signature verification failed";
      }
    }

    // -----------------------------------------------------------------------
    // 2. Manifest checks
    // -----------------------------------------------------------------------
    if (!opts.manifest) {
      missing.push("MISSING_MANIFEST");
      descriptions["MISSING_MANIFEST"] = "A pre-action Attestation Manifest is required";
    } else {
      const m = opts.manifest;

      // Expiry
      if (new Date(m.valid_until).getTime() < nowMs) {
        missing.push("EXPIRED_MANIFEST");
        descriptions["EXPIRED_MANIFEST"] = `Manifest expired at ${m.valid_until}`;
      }

      // DID consistency: passport.agent_did must match manifest.agent_did
      if (opts.passport && opts.passport.agent_did !== m.agent_did) {
        missing.push("DID_MISMATCH");
        descriptions["DID_MISMATCH"] = `Passport DID ${opts.passport.agent_did} ≠ manifest DID ${m.agent_did}`;
      }

      // Signature (manifest signed by agent key embedded in passport)
      let manifestSigOk = false;
      try {
        const agentPubB64u = opts.passport?.public_key_b64u ?? m.key_id;
        const pubBytes = b64uDecode(agentPubB64u);
        const sigBytes = b64uDecode(m.signature);
        const bodyBytes = manifestSigningBody(m);
        manifestSigOk = ed.verify(sigBytes, bodyBytes, pubBytes);
      } catch {
        manifestSigOk = false;
      }
      if (!manifestSigOk) {
        missing.push("INVALID_MANIFEST_SIGNATURE");
        descriptions["INVALID_MANIFEST_SIGNATURE"] = "Manifest signature verification failed";
      }

      // Cargo policy checks
      for (const policy of this.policies) {
        if (policy.resource !== m.target_resource && policy.resource !== "*") continue;

        const cargoSet = new Set(m.declared_cargo);

        // Required cargo
        for (const req of policy.required_cargo ?? []) {
          if (!cargoSet.has(req)) {
            const code: MissingPrereqCode = "CARGO_MISMATCH";
            if (!missing.includes(code)) {
              missing.push(code);
              descriptions[code] = `Required cargo "${req}" not declared`;
            }
          }
        }

        // Forbidden cargo
        for (const forbidden of policy.forbidden_cargo ?? []) {
          if (cargoSet.has(forbidden)) {
            const code: MissingPrereqCode = "FORBIDDEN_CARGO";
            if (!missing.includes(code)) {
              missing.push(code);
              descriptions[code] = `Forbidden cargo "${forbidden}" was declared`;
            }
          }
        }
      }
    }

    // -----------------------------------------------------------------------
    // Decision
    // -----------------------------------------------------------------------
    if (missing.length > 0) {
      const challenge: GateChallenge = {
        scheme: "HiveAttest",
        realm: this.realm,
        missing,
        descriptions: descriptions as Record<MissingPrereqCode, string>,
      };
      return { allowed: false, challenge };
    }

    // Allowed — compute fingerprint over decision
    const decisionId = randomUUID();
    const decisionBody = canonicalize({
      decision_id: decisionId,
      allowed: true,
      manifest_id: opts.manifest!.manifest_id,
      agent_did: opts.manifest!.agent_did,
      evaluated_at: new Date(nowMs).toISOString(),
    });
    const fingerprint = sha256Hex(decisionBody);

    return { allowed: true, decisionId, fingerprint };
  }

  /** Build the WWW-Authenticate header value for a failed gate decision. */
  static formatChallenge(challenge: GateChallenge): string {
    const missingStr = challenge.missing.join(" ");
    return `${challenge.scheme} realm="${challenge.realm}" missing="${missingStr}"`;
  }
}
