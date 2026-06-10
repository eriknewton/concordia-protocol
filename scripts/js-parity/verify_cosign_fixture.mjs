// Cross-runtime parity harness for the counterparty co-signature.
//
// Verifies the Concordia-produced fixture
// (tests/fixtures/concordia_cosigned_receipt.json) on the SAME runtime
// Verascore runs on — V8 / Node — using a faithful copy of Verascore's
// verascore/src/lib/concordia-cosignature.ts + crypto.ts. This is the
// strongest parity check: if Concordia's Python canonical_json diverged from
// V8's JSON.stringify (string escaping, number formatting, key sort), the
// Ed25519 signature produced by the Python producer would fail to verify here.
//
// The functions below are copied byte-for-logic from the TS source so this
// stays bound to it. Exits 0 on PASS, 1 on verification failure, 2 on error.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { createPublicKey, verify } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");
const fixturePath = join(
  repoRoot,
  "tests",
  "fixtures",
  "concordia_cosigned_receipt.json",
);

// ── Copy of concordia-cosignature.ts: stripSignatures ──────────────
function stripSignatures(value) {
  if (Array.isArray(value)) return value.map(stripSignatures);
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === "signature") continue;
      out[k] = stripSignatures(v);
    }
    return out;
  }
  return value;
}

// ── Copy of concordia-cosignature.ts: stableStringify ──────────────
function stableStringify(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(value[k])).join(",") + "}";
  }
  throw new Error(`Cannot canonicalize type: ${typeof value}`);
}

function canonicalCosignBytes(receipt) {
  return Buffer.from(stableStringify(stripSignatures(receipt)), "utf-8");
}

// ── Copy of crypto.ts: base64urlToBuffer ───────────────────────────
function base64urlToBuffer(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (base64.length % 4)) % 4;
  return Buffer.from(base64 + "=".repeat(padding), "base64");
}

// ── Copy of crypto.ts: publicKeyFromDid (base64url Ed25519 branch) ──
function publicKeyFromDid(did) {
  if (!did.startsWith("did:key:z")) return null;
  const encoded = did.slice("did:key:z".length);
  try {
    const decoded = base64urlToBuffer(encoded);
    if (decoded.length === 34 && decoded[0] === 0xed && decoded[1] === 0x01) {
      return decoded.subarray(2);
    }
  } catch {
    // fall through
  }
  return null;
}

// ── Copy of crypto.ts: verifyEd25519 ───────────────────────────────
function verifyEd25519(message, signature, publicKeyRaw) {
  try {
    const derPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const publicKeyDer = Buffer.concat([derPrefix, publicKeyRaw]);
    const publicKey = createPublicKey({ key: publicKeyDer, format: "der", type: "spki" });
    return verify(null, message, publicKey, signature);
  } catch {
    return false;
  }
}

// ── Copy of concordia-cosignature.ts: findCounterpartySignature ────
function findCounterpartySignature(receipt, counterpartyDid) {
  const parties = Array.isArray(receipt.parties) ? receipt.parties : [];
  const matches = parties.filter(
    (p) => p && typeof p === "object" &&
      (p.agent_id === counterpartyDid || p.agentId === counterpartyDid),
  );
  if (matches.length !== 1) return null;
  const sig = matches[0].signature;
  return typeof sig === "string" && sig.length > 0 ? sig : null;
}

// ── Copy of concordia-cosignature.ts: verifyCounterpartyCosignatureStructural
function verifyCounterpartyCosignatureStructural(receipt, counterpartyDid, publisherDid) {
  try {
    if (!receipt || typeof receipt !== "object") return false;
    if (!counterpartyDid || !counterpartyDid.startsWith("did:key:")) return false;
    if (!publisherDid) return false;
    if (counterpartyDid === publisherDid) return false;
    const counterpartyKey = publicKeyFromDid(counterpartyDid);
    if (!counterpartyKey) return false;
    const sigB64 = findCounterpartySignature(receipt, counterpartyDid);
    if (!sigB64) return false;
    const signature = base64urlToBuffer(sigB64);
    if (signature.length !== 64) return false;
    const message = canonicalCosignBytes(receipt);
    return verifyEd25519(message, signature, counterpartyKey);
  } catch {
    return false;
  }
}

function main() {
  let fixture;
  try {
    fixture = JSON.parse(readFileSync(fixturePath, "utf-8"));
  } catch (err) {
    console.error(`[ERROR] cannot read fixture ${fixturePath}: ${err.message}`);
    process.exit(2);
  }

  const ok = verifyCounterpartyCosignatureStructural(
    fixture.receipt,
    fixture.counterparty_did,
    fixture.publisher_did,
  );

  if (ok && fixture.expected_counterparty_verified === true) {
    console.log("PARITY: cosign fixture verifies under V8/Node Verascore port");
    process.exit(0);
  }
  console.log(
    `PARITY FAIL: verify=${ok}, expected=${fixture.expected_counterparty_verified}`,
  );
  process.exit(1);
}

main();
