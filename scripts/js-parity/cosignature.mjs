// Shared counterparty co-signature helpers for the JS parity harness.
//
// The canonicalization function is Concordia's JavaScript implementation of
// RFC 8785 JCS for JSON values. The co-signature byte contract applies
// Concordia's recursive signature-stripping rule before canonicalization.

import { createPublicKey, verify } from "node:crypto";

export function stripSignatures(value) {
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

export function stableStringify(value) {
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
    return (
      "{" +
      keys
        .map((k) => JSON.stringify(k) + ":" + stableStringify(value[k]))
        .join(",") +
      "}"
    );
  }
  throw new Error(`Cannot canonicalize type: ${typeof value}`);
}

export function canonicalCosignBytes(receipt) {
  return Buffer.from(stableStringify(stripSignatures(receipt)), "utf-8");
}

export function base64urlToBuffer(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (base64.length % 4)) % 4;
  return Buffer.from(base64 + "=".repeat(padding), "base64");
}

export function publicKeyFromDid(did) {
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

export function verifyEd25519(message, signature, publicKeyRaw) {
  try {
    const derPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const publicKeyDer = Buffer.concat([derPrefix, publicKeyRaw]);
    const publicKey = createPublicKey({
      key: publicKeyDer,
      format: "der",
      type: "spki",
    });
    return verify(null, message, publicKey, signature);
  } catch {
    return false;
  }
}

export function findCounterpartySignature(receipt, counterpartyDid) {
  const parties = Array.isArray(receipt.parties) ? receipt.parties : [];
  const matches = parties.filter(
    (p) =>
      p &&
      typeof p === "object" &&
      (p.agent_id === counterpartyDid || p.agentId === counterpartyDid),
  );
  if (matches.length !== 1) return null;
  const sig = matches[0].signature;
  return typeof sig === "string" && sig.length > 0 ? sig : null;
}

export function verifyCounterpartyCosignatureStructural(
  receipt,
  counterpartyDid,
  publisherDid,
) {
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
