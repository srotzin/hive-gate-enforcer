/**
 * Tests for hive-gate-enforcer (C19 — Gate Enforcement).
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { GateEnforcer, GateCredentialIssuer } from "../src/gate.js";
import type {
  GateManifest,
  GatePolicy,
  HivePassportCredential,
} from "../src/types.js";

// Required: wire sha512Sync for @noble/ed25519
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const AUTHORITY_KEY = new Uint8Array(32).fill(0xaa);
const AGENT_KEY = new Uint8Array(32).fill(0xbb);
const OTHER_KEY = new Uint8Array(32).fill(0xcc);
const BAD_KEY = new Uint8Array(32).fill(0xdd);

let issuer: GateCredentialIssuer;
let agentPubB64u: string;

// Build a deterministic b64url encoder
function b64uEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

const AGENT_DID = "did:hive:agent-primary";
const OTHER_DID = "did:hive:agent-other";

const NOW_MS = 1_700_000_000_000; // fixed epoch for deterministic tests

beforeAll(() => {
  issuer = new GateCredentialIssuer(AUTHORITY_KEY);
  agentPubB64u = b64uEncode(ed.getPublicKey(AGENT_KEY));
});

function makeEnforcer(policies?: GatePolicy[]) {
  return new GateEnforcer({
    authorityPubKeyB64u: issuer.publicKeyB64u,
    realm: "test-realm",
    policies,
  });
}

function freshPassport(opts?: Partial<{ ttlSeconds: number; nowMs: number }>) {
  return issuer.issuePassport({
    agentDid: AGENT_DID,
    agentPubKeyB64u: agentPubB64u,
    ttlSeconds: opts?.ttlSeconds ?? 3600,
    nowMs: opts?.nowMs ?? NOW_MS,
  });
}

function freshManifest(
  opts?: Partial<{
    agentDid: string;
    agentPrivKey: Uint8Array;
    declaredCargo: string[];
    targetResource: string;
    ttlSeconds: number;
    nowMs: number;
  }>
) {
  return issuer.issueManifest({
    agentDid: opts?.agentDid ?? AGENT_DID,
    agentPrivKey: opts?.agentPrivKey ?? AGENT_KEY,
    declaredCargo: opts?.declaredCargo ?? [],
    targetResource: opts?.targetResource ?? "https://api.example.com",
    ttlSeconds: opts?.ttlSeconds ?? 300,
    nowMs: opts?.nowMs ?? NOW_MS,
  });
}

// ---------------------------------------------------------------------------
// SECTION 1: Basic allowed decisions
// ---------------------------------------------------------------------------

describe("GateEnforcer — allowed decisions", () => {
  it("allows a request with valid passport and manifest", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest(),
      nowMs: NOW_MS,
    });
    expect(d.allowed).toBe(true);
    expect(d.challenge).toBeUndefined();
  });

  it("allowed decision has a decisionId", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest(),
      nowMs: NOW_MS,
    });
    expect(d.decisionId).toBeDefined();
    expect(typeof d.decisionId).toBe("string");
    expect(d.decisionId!.length).toBeGreaterThan(0);
  });

  it("allowed decision has a hex fingerprint (64 chars)", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest(),
      nowMs: NOW_MS,
    });
    expect(d.fingerprint).toBeDefined();
    expect(d.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("two separate allowed decisions produce different decisionIds", async () => {
    const e = makeEnforcer();
    const [d1, d2] = await Promise.all([
      e.evaluate({ passport: freshPassport(), manifest: freshManifest(), nowMs: NOW_MS }),
      e.evaluate({ passport: freshPassport(), manifest: freshManifest(), nowMs: NOW_MS + 1 }),
    ]);
    // decisionIds come from UUID — they should differ (different nowMs → different eval body)
    expect(d1.allowed).toBe(true);
    expect(d2.allowed).toBe(true);
  });

  it("allows request with required cargo satisfied", async () => {
    const e = makeEnforcer([
      { resource: "https://api.example.com", required_cargo: ["pii"] },
    ]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ declaredCargo: ["pii", "logs"] }),
      nowMs: NOW_MS,
    });
    expect(d.allowed).toBe(true);
  });

  it("allows when policy resource has wildcard '*'", async () => {
    const e = makeEnforcer([{ resource: "*", required_cargo: ["logs"] }]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ declaredCargo: ["logs"] }),
      nowMs: NOW_MS,
    });
    expect(d.allowed).toBe(true);
  });

  it("ignores policy for non-matching resource", async () => {
    const e = makeEnforcer([
      { resource: "https://other.example.com", required_cargo: ["secret"] },
    ]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ targetResource: "https://api.example.com" }),
      nowMs: NOW_MS,
    });
    expect(d.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// SECTION 2: Missing passport
// ---------------------------------------------------------------------------

describe("GateEnforcer — passport missing", () => {
  it("rejects when passport is null", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({
      passport: null,
      manifest: freshManifest(),
      nowMs: NOW_MS,
    });
    expect(d.allowed).toBe(false);
    expect(d.challenge?.missing).toContain("MISSING_PASSPORT");
  });

  it("missing passport challenge has realm set", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: null, manifest: freshManifest(), nowMs: NOW_MS });
    expect(d.challenge?.realm).toBe("test-realm");
  });

  it("missing passport description is populated", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: null, manifest: freshManifest(), nowMs: NOW_MS });
    expect(d.challenge?.descriptions["MISSING_PASSPORT"]).toBeTruthy();
  });

  it("missing passport does not check manifest DID (no passport to compare)", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: null, manifest: freshManifest(), nowMs: NOW_MS });
    expect(d.challenge?.missing).not.toContain("DID_MISMATCH");
  });
});

// ---------------------------------------------------------------------------
// SECTION 3: Expired passport
// ---------------------------------------------------------------------------

describe("GateEnforcer — passport expired", () => {
  it("rejects when passport is expired", async () => {
    const e = makeEnforcer();
    const p = freshPassport({ ttlSeconds: -1, nowMs: NOW_MS });
    const d = await e.evaluate({ passport: p, manifest: freshManifest(), nowMs: NOW_MS });
    expect(d.allowed).toBe(false);
    expect(d.challenge?.missing).toContain("EXPIRED_PASSPORT");
  });

  it("expired passport has description", async () => {
    const e = makeEnforcer();
    const p = freshPassport({ ttlSeconds: -1, nowMs: NOW_MS });
    const d = await e.evaluate({ passport: p, manifest: freshManifest(), nowMs: NOW_MS });
    expect(d.challenge?.descriptions["EXPIRED_PASSPORT"]).toMatch(/expired/i);
  });

  it("passport with exactly zero TTL is expired", async () => {
    const e = makeEnforcer();
    const p = freshPassport({ ttlSeconds: 0, nowMs: NOW_MS });
    const d = await e.evaluate({ passport: p, manifest: freshManifest(), nowMs: NOW_MS + 1 });
    expect(d.challenge?.missing).toContain("EXPIRED_PASSPORT");
  });
});

// ---------------------------------------------------------------------------
// SECTION 4: Invalid passport signature
// ---------------------------------------------------------------------------

describe("GateEnforcer — passport signature", () => {
  it("rejects passport with tampered signature", async () => {
    const e = makeEnforcer();
    const p = { ...freshPassport(), signature: b64uEncode(new Uint8Array(64).fill(0xff)) };
    const d = await e.evaluate({ passport: p, manifest: freshManifest(), nowMs: NOW_MS });
    expect(d.challenge?.missing).toContain("INVALID_PASSPORT_SIGNATURE");
  });

  it("rejects passport signed by wrong authority", async () => {
    const wrongIssuer = new GateCredentialIssuer(OTHER_KEY);
    const badPassport = wrongIssuer.issuePassport({
      agentDid: AGENT_DID,
      agentPubKeyB64u: agentPubB64u,
      ttlSeconds: 3600,
      nowMs: NOW_MS,
    });
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: badPassport, manifest: freshManifest(), nowMs: NOW_MS });
    expect(d.challenge?.missing).toContain("INVALID_PASSPORT_SIGNATURE");
  });

  it("rejects passport with empty signature string", async () => {
    const e = makeEnforcer();
    const p = { ...freshPassport(), signature: "" };
    const d = await e.evaluate({ passport: p, manifest: freshManifest(), nowMs: NOW_MS });
    expect(d.challenge?.missing).toContain("INVALID_PASSPORT_SIGNATURE");
  });
});

// ---------------------------------------------------------------------------
// SECTION 5: Missing manifest
// ---------------------------------------------------------------------------

describe("GateEnforcer — manifest missing", () => {
  it("rejects when manifest is null", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: freshPassport(), manifest: null, nowMs: NOW_MS });
    expect(d.allowed).toBe(false);
    expect(d.challenge?.missing).toContain("MISSING_MANIFEST");
  });

  it("missing manifest populates description", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: freshPassport(), manifest: null, nowMs: NOW_MS });
    expect(d.challenge?.descriptions["MISSING_MANIFEST"]).toBeTruthy();
  });

  it("both passport and manifest null triggers both codes", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: null, manifest: null, nowMs: NOW_MS });
    expect(d.challenge?.missing).toContain("MISSING_PASSPORT");
    expect(d.challenge?.missing).toContain("MISSING_MANIFEST");
  });
});

// ---------------------------------------------------------------------------
// SECTION 6: Expired manifest
// ---------------------------------------------------------------------------

describe("GateEnforcer — manifest expired", () => {
  it("rejects expired manifest", async () => {
    const e = makeEnforcer();
    const m = freshManifest({ ttlSeconds: -1, nowMs: NOW_MS });
    const d = await e.evaluate({ passport: freshPassport(), manifest: m, nowMs: NOW_MS });
    expect(d.challenge?.missing).toContain("EXPIRED_MANIFEST");
  });

  it("manifest with zero TTL is expired after one ms", async () => {
    const e = makeEnforcer();
    const m = freshManifest({ ttlSeconds: 0, nowMs: NOW_MS });
    const d = await e.evaluate({ passport: freshPassport(), manifest: m, nowMs: NOW_MS + 1 });
    expect(d.challenge?.missing).toContain("EXPIRED_MANIFEST");
  });

  it("expired manifest description mentions expiry timestamp", async () => {
    const e = makeEnforcer();
    const m = freshManifest({ ttlSeconds: -60, nowMs: NOW_MS });
    const d = await e.evaluate({ passport: freshPassport(), manifest: m, nowMs: NOW_MS });
    expect(d.challenge?.descriptions["EXPIRED_MANIFEST"]).toMatch(/expired/i);
  });
});

// ---------------------------------------------------------------------------
// SECTION 7: Invalid manifest signature
// ---------------------------------------------------------------------------

describe("GateEnforcer — manifest signature", () => {
  it("rejects manifest with tampered signature", async () => {
    const e = makeEnforcer();
    const m = { ...freshManifest(), signature: b64uEncode(new Uint8Array(64).fill(0x01)) };
    const d = await e.evaluate({ passport: freshPassport(), manifest: m, nowMs: NOW_MS });
    expect(d.challenge?.missing).toContain("INVALID_MANIFEST_SIGNATURE");
  });

  it("rejects manifest signed by wrong key", async () => {
    const e = makeEnforcer();
    const m = freshManifest({ agentPrivKey: BAD_KEY });
    const d = await e.evaluate({ passport: freshPassport(), manifest: m, nowMs: NOW_MS });
    expect(d.challenge?.missing).toContain("INVALID_MANIFEST_SIGNATURE");
  });

  it("rejects manifest with empty signature", async () => {
    const e = makeEnforcer();
    const m = { ...freshManifest(), signature: "" };
    const d = await e.evaluate({ passport: freshPassport(), manifest: m, nowMs: NOW_MS });
    expect(d.challenge?.missing).toContain("INVALID_MANIFEST_SIGNATURE");
  });
});

// ---------------------------------------------------------------------------
// SECTION 8: DID mismatch
// ---------------------------------------------------------------------------

describe("GateEnforcer — DID mismatch", () => {
  it("rejects when manifest DID differs from passport DID", async () => {
    const e = makeEnforcer();
    const otherPubB64u = b64uEncode(ed.getPublicKey(OTHER_KEY));
    const passport = issuer.issuePassport({
      agentDid: AGENT_DID,
      agentPubKeyB64u: agentPubB64u,
      ttlSeconds: 3600,
      nowMs: NOW_MS,
    });
    const manifest = freshManifest({ agentDid: OTHER_DID, agentPrivKey: OTHER_KEY });
    const d = await e.evaluate({ passport, manifest, nowMs: NOW_MS });
    expect(d.challenge?.missing).toContain("DID_MISMATCH");
  });

  it("DID mismatch description mentions both DIDs", async () => {
    const e = makeEnforcer();
    const passport = issuer.issuePassport({
      agentDid: AGENT_DID,
      agentPubKeyB64u: agentPubB64u,
      ttlSeconds: 3600,
      nowMs: NOW_MS,
    });
    const manifest = freshManifest({ agentDid: OTHER_DID, agentPrivKey: OTHER_KEY });
    const d = await e.evaluate({ passport, manifest, nowMs: NOW_MS });
    expect(d.challenge?.descriptions["DID_MISMATCH"]).toContain(AGENT_DID);
  });
});

// ---------------------------------------------------------------------------
// SECTION 9: Cargo policy
// ---------------------------------------------------------------------------

describe("GateEnforcer — cargo policies", () => {
  it("rejects when required cargo is missing", async () => {
    const e = makeEnforcer([
      { resource: "https://api.example.com", required_cargo: ["pii"] },
    ]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ declaredCargo: [] }),
      nowMs: NOW_MS,
    });
    expect(d.challenge?.missing).toContain("CARGO_MISMATCH");
  });

  it("rejects when forbidden cargo is present", async () => {
    const e = makeEnforcer([
      { resource: "https://api.example.com", forbidden_cargo: ["secret"] },
    ]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ declaredCargo: ["secret"] }),
      nowMs: NOW_MS,
    });
    expect(d.challenge?.missing).toContain("FORBIDDEN_CARGO");
  });

  it("cargo mismatch description names the missing type", async () => {
    const e = makeEnforcer([
      { resource: "https://api.example.com", required_cargo: ["biometrics"] },
    ]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ declaredCargo: [] }),
      nowMs: NOW_MS,
    });
    expect(d.challenge?.descriptions["CARGO_MISMATCH"]).toContain("biometrics");
  });

  it("forbidden cargo description names the forbidden type", async () => {
    const e = makeEnforcer([
      { resource: "https://api.example.com", forbidden_cargo: ["classified"] },
    ]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ declaredCargo: ["classified"] }),
      nowMs: NOW_MS,
    });
    expect(d.challenge?.descriptions["FORBIDDEN_CARGO"]).toContain("classified");
  });

  it("only applies cargo policy to matching resource", async () => {
    const e = makeEnforcer([
      { resource: "https://other.example.com", required_cargo: ["secret"] },
    ]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ targetResource: "https://api.example.com" }),
      nowMs: NOW_MS,
    });
    expect(d.allowed).toBe(true);
  });

  it("cargo mismatch de-duped if multiple required cargo missing", async () => {
    const e = makeEnforcer([
      {
        resource: "https://api.example.com",
        required_cargo: ["a", "b", "c"],
      },
    ]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ declaredCargo: [] }),
      nowMs: NOW_MS,
    });
    expect(d.challenge?.missing.filter((c) => c === "CARGO_MISMATCH").length).toBe(1);
  });

  it("wildcard '*' policy applies to all resources", async () => {
    const e = makeEnforcer([{ resource: "*", required_cargo: ["audit-log"] }]);
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest({ targetResource: "https://anything.example.com" }),
      nowMs: NOW_MS,
    });
    expect(d.challenge?.missing).toContain("CARGO_MISMATCH");
  });
});

// ---------------------------------------------------------------------------
// SECTION 10: formatChallenge
// ---------------------------------------------------------------------------

describe("GateEnforcer.formatChallenge", () => {
  it("formats a single missing code", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: null, manifest: null, nowMs: NOW_MS });
    const header = GateEnforcer.formatChallenge(d.challenge!);
    expect(header).toContain("HiveAttest");
    expect(header).toContain("realm=");
    expect(header).toContain("missing=");
  });

  it("formatted header contains all missing codes", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: null, manifest: null, nowMs: NOW_MS });
    const header = GateEnforcer.formatChallenge(d.challenge!);
    for (const code of d.challenge!.missing) {
      expect(header).toContain(code);
    }
  });

  it("formatted header has scheme=HiveAttest prefix", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: null, manifest: null, nowMs: NOW_MS });
    const header = GateEnforcer.formatChallenge(d.challenge!);
    expect(header.startsWith("HiveAttest ")).toBe(true);
  });

  it("realm appears in double-quotes in formatted header", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: null, manifest: null, nowMs: NOW_MS });
    const header = GateEnforcer.formatChallenge(d.challenge!);
    expect(header).toContain('realm="test-realm"');
  });
});

// ---------------------------------------------------------------------------
// SECTION 11: Multi-failure accumulation
// ---------------------------------------------------------------------------

describe("GateEnforcer — multiple simultaneous failures", () => {
  it("accumulates passport + manifest failures in missing array", async () => {
    const e = makeEnforcer();
    const expiredPassport = freshPassport({ ttlSeconds: -1, nowMs: NOW_MS });
    const expiredManifest = freshManifest({ ttlSeconds: -1, nowMs: NOW_MS });
    const d = await e.evaluate({
      passport: expiredPassport,
      manifest: expiredManifest,
      nowMs: NOW_MS,
    });
    expect(d.challenge?.missing).toContain("EXPIRED_PASSPORT");
    expect(d.challenge?.missing).toContain("EXPIRED_MANIFEST");
  });

  it("all four codes can appear simultaneously", async () => {
    const e = makeEnforcer([
      { resource: "https://api.example.com", required_cargo: ["x"], forbidden_cargo: ["y"] },
    ]);
    const badManifest: GateManifest = {
      ...freshManifest({ declaredCargo: ["y"], ttlSeconds: -1, nowMs: NOW_MS }),
      signature: b64uEncode(new Uint8Array(64)),
      agent_did: OTHER_DID,
    };
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: badManifest,
      nowMs: NOW_MS,
    });
    expect(d.allowed).toBe(false);
    expect(d.challenge?.missing.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// SECTION 12: GateCredentialIssuer
// ---------------------------------------------------------------------------

describe("GateCredentialIssuer", () => {
  it("throws on non-32-byte key", () => {
    expect(() => new GateCredentialIssuer(new Uint8Array(16))).toThrow();
  });

  it("publicKeyB64u is 43-44 char base64url string", () => {
    const i = new GateCredentialIssuer(AUTHORITY_KEY);
    expect(i.publicKeyB64u).toMatch(/^[A-Za-z0-9_-]{43,44}$/);
  });

  it("issuePassport returns all required fields", () => {
    const p = issuer.issuePassport({
      agentDid: AGENT_DID,
      agentPubKeyB64u: agentPubB64u,
      nowMs: NOW_MS,
    });
    expect(p.agent_did).toBe(AGENT_DID);
    expect(p.public_key_b64u).toBe(agentPubB64u);
    expect(p.authority_key_id).toBe(issuer.publicKeyB64u);
    expect(p.signature).toBeDefined();
    expect(p.expires_at).toBeDefined();
  });

  it("issueManifest returns all required fields", () => {
    const m = freshManifest();
    expect(m.manifest_id).toBeDefined();
    expect(m.agent_did).toBe(AGENT_DID);
    expect(m.signature).toBeDefined();
    expect(m.declared_cargo).toBeInstanceOf(Array);
  });

  it("issueManifest uses default cargo []", () => {
    const m = freshManifest();
    expect(m.declared_cargo).toEqual([]);
  });

  it("issued passport verifies in GateEnforcer", async () => {
    const e = makeEnforcer();
    const p = freshPassport();
    const m = freshManifest();
    const d = await e.evaluate({ passport: p, manifest: m, nowMs: NOW_MS });
    expect(d.allowed).toBe(true);
  });

  it("two different agents produce different fingerprints", async () => {
    const issuer2 = new GateCredentialIssuer(OTHER_KEY);
    const otherPub = b64uEncode(ed.getPublicKey(OTHER_KEY));

    const e = makeEnforcer();
    const p1 = issuer.issuePassport({
      agentDid: AGENT_DID,
      agentPubKeyB64u: agentPubB64u,
      ttlSeconds: 3600,
      nowMs: NOW_MS,
    });
    const m1 = freshManifest();
    const d1 = await e.evaluate({ passport: p1, manifest: m1, nowMs: NOW_MS });

    // Second agent uses wrong authority → will be rejected
    const e2 = new GateEnforcer({
      authorityPubKeyB64u: issuer2.publicKeyB64u,
    });
    const p2 = issuer2.issuePassport({
      agentDid: OTHER_DID,
      agentPubKeyB64u: otherPub,
      ttlSeconds: 3600,
      nowMs: NOW_MS,
    });
    const m2 = issuer2.issueManifest({
      agentDid: OTHER_DID,
      agentPrivKey: OTHER_KEY,
      nowMs: NOW_MS,
    });
    const d2 = await e2.evaluate({ passport: p2, manifest: m2, nowMs: NOW_MS + 1 });

    // At least one allowed → fingerprints are defined
    expect(d1.allowed).toBe(true);
    expect(d2.allowed).toBe(true);
    expect(d1.fingerprint).not.toBe(d2.fingerprint);
  });
});

// ---------------------------------------------------------------------------
// SECTION 13: GateEnforcer defaults
// ---------------------------------------------------------------------------

describe("GateEnforcer — defaults", () => {
  it("accepts no policies option (defaults to empty)", async () => {
    const e = new GateEnforcer({ authorityPubKeyB64u: issuer.publicKeyB64u });
    const d = await e.evaluate({
      passport: freshPassport(),
      manifest: freshManifest(),
      nowMs: NOW_MS,
    });
    expect(d.allowed).toBe(true);
  });

  it("default realm is 'hive-gate'", async () => {
    const e = new GateEnforcer({ authorityPubKeyB64u: issuer.publicKeyB64u });
    const d = await e.evaluate({ passport: null, manifest: null, nowMs: NOW_MS });
    expect(d.challenge?.realm).toBe("hive-gate");
  });

  it("challenge scheme is always 'HiveAttest'", async () => {
    const e = makeEnforcer();
    const d = await e.evaluate({ passport: null, manifest: null, nowMs: NOW_MS });
    expect(d.challenge?.scheme).toBe("HiveAttest");
  });
});
