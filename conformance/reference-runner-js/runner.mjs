#!/usr/bin/env node
import Ajv2020 from "ajv/dist/2020.js";
import {
  createPrivateKey,
  createPublicKey,
  createHash,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const VECTOR_SCHEMA_VERSION = "concordia-conformance-vector/v1-draft";
const PROFILE_ORDER = new Set([
  "decision-object-v1",
  "offer-binding-v1",
  "receipt-v1",
  "revocation-v1",
  "cascade-decision-v1",
  "fulfillment-attestation-v1",
  "attestation-v1",
  "attestation-countersign-v1",
  "predicate-v1",
  "mandate-v1",
  "delegation-chain-v1",
  "cosign-v1",
  "conditional-commitment-v1",
  "atomic-activation-proof-v1",
  "unwind-record-v1",
  "closure-predicate-v1",
  "chain-session-v1",
  "chain-session-transition-v1",
  "agent-profile-v1",
  "competence-proof-v1",
  "receipt-bundle-v1",
  "message-chain-v1",
]);
const RECORD_TYPES = new Set([
  "decision_object",
  "approval_receipt",
  "revocation_record",
  "cascade_decision_record",
  "fulfillment_attestation",
  "attestation",
  "predicate",
  "mandate",
  "cosign_receipt",
  "conditional_commitment",
  "atomic_activation_proof",
  "unwind_record",
  "closure_predicate",
  "chain_session",
  "chain_session_transition",
  "agent_profile",
  "competence_proof",
  "receipt_bundle",
  "message_chain",
]);
const REQUIRED_VECTOR_FIELDS = new Set([
  "schema_version",
  "id",
  "title",
  "source_fixture",
  "record_type",
  "verification_profile",
  "input",
  "context",
  "expected",
]);
const RAW_TERM_PATTERNS = [
  /[$€£¥]\s*\d/i,
  /\b(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\s*\d/i,
  /\b\d+(?:[.,]\d+)?\s*(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\b/i,
  /\bprice\s*:/i,
  /\b(?:qty|quantity)\s*[:=]?\s*\d+\b/i,
  /\b\d+\s*(?:units?|items?|pcs|pieces)\b/i,
];
const LEGAL_CHAIN_TRANSITIONS = new Map([
  ["PROPOSED", new Set(["OPEN"])],
  ["OPEN", new Set(["ACTIVATED", "DISSOLVED", "EXPIRED"])],
  ["ACTIVATED", new Set()],
  ["DISSOLVED", new Set()],
  ["EXPIRED", new Set()],
]);
const AGENT_PROFILE_CANONICAL_FIELDS = [
  "type",
  "version",
  "agent_id",
  "name",
  "description",
  "capabilities",
  "negotiation_profile",
  "trust_signals",
  "endpoints",
  "location",
  "ttl",
  "updated_at",
];
const AGENT_PROFILE_TOP_LEVEL_FIELDS = new Set([
  ...AGENT_PROFILE_CANONICAL_FIELDS,
  "signature",
  "verified",
]);
const AGENT_PROFILE_CAPABILITY_FIELDS = new Set([
  "categories",
  "offer_types",
  "resolution_methods",
  "max_concurrent_sessions",
  "languages",
  "currencies",
]);
const AGENT_PROFILE_NEGOTIATION_FIELDS = new Set([
  "style",
  "avg_rounds_to_agreement",
  "agreement_rate",
  "avg_session_duration_seconds",
  "concession_pattern",
]);
const AGENT_PROFILE_TRUST_SIGNAL_FIELDS = new Set([
  "verascore_did",
  "verascore_tier",
  "verascore_composite",
  "sovereignty",
  "concordia_sessions_completed",
  "attestation_count",
  "concordia_preferred",
  "reputation",
]);
const AGENT_PROFILE_SOVEREIGNTY_FIELDS = new Set(["L1", "L2", "L3", "L4"]);
const AGENT_PROFILE_REPUTATION_FIELDS = new Set([
  "provider",
  "subject_did",
  "tier",
  "composite",
]);
const AGENT_PROFILE_ENDPOINT_FIELDS = new Set([
  "negotiate",
  "a2a_card",
  "mcp_manifest",
]);
const AGENT_PROFILE_LOCATION_FIELDS = new Set(["regions", "jurisdictions"]);
const GENESIS_HASH = `sha256:${"0".repeat(64)}`;
const SEMVER_RE = /^\d+\.\d+\.\d+$/u;
const SHA256_HEX_RE = /^sha256:[a-f0-9]{64}$/u;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

const schemaContexts = new Map();

class Reject extends Error {}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(message) {
  throw new Reject(message);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function b64urlDecode(value) {
  if (typeof value !== "string") {
    reject("base64url value is not a string");
  }
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value) || /=[A-Za-z0-9_-]/.test(value)) {
    reject("invalid base64url value");
  }
  const unpadded = value.replace(/=+$/, "");
  if (unpadded.length % 4 === 1) {
    reject("invalid base64url value");
  }
  const padded = `${unpadded}${"=".repeat((4 - (unpadded.length % 4)) % 4)}`;
  try {
    return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  } catch (error) {
    reject("invalid base64url value");
  }
}

function b64urlEncode(value) {
  return Buffer.from(value).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function jcs(value) {
  if (value === null) {
    return "null";
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      reject("JCS canonicalization failed");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => jcs(item)).join(",")}]`;
  }
  if (isObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`)
      .join(",")}}`;
  }
  reject("JCS canonicalization failed");
}

function jcsBytes(value) {
  return Buffer.from(jcs(value), "utf8");
}

function sha256Bytes(payload) {
  return createHash("sha256").update(payload).digest("hex");
}

function sha256Jcs(value) {
  return `sha256:${sha256Bytes(jcsBytes(value))}`;
}

function canonicalSha256(payload) {
  return `sha256:${sha256Bytes(payload)}`;
}

function withoutTopLevel(data, keys) {
  if (!isObject(data)) {
    reject("input is not an object");
  }
  const result = {};
  for (const [key, value] of Object.entries(data)) {
    if (!keys.has(key)) {
      result[key] = value;
    }
  }
  return result;
}

function parseIsoMillis(value, { requireTimezone }) {
  if (typeof value !== "string") {
    reject("timestamp is not a string");
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/.exec(
    value,
  );
  if (match === null) {
    reject("timestamp is invalid");
  }
  const [, yearRaw, monthRaw, dayRaw, hourRaw, minuteRaw, secondRaw, fractionRaw, zoneRaw] =
    match;
  if (requireTimezone && zoneRaw === undefined) {
    reject("timestamp is invalid");
  }
  const year = Number(yearRaw);
  const month = Number(monthRaw);
  const day = Number(dayRaw);
  const hour = Number(hourRaw);
  const minute = Number(minuteRaw);
  const second = Number(secondRaw);
  const millis = fractionRaw === undefined ? 0 : Number((fractionRaw.slice(1) + "000").slice(0, 3));
  const localMillis = Date.UTC(year, month - 1, day, hour, minute, second, millis);
  const localDate = new Date(localMillis);
  if (
    localDate.getUTCFullYear() !== year ||
    localDate.getUTCMonth() !== month - 1 ||
    localDate.getUTCDate() !== day ||
    localDate.getUTCHours() !== hour ||
    localDate.getUTCMinutes() !== minute ||
    localDate.getUTCSeconds() !== second
  ) {
    reject("timestamp is invalid");
  }
  let offsetMillis = 0;
  if (zoneRaw !== undefined && zoneRaw !== "Z") {
    const sign = zoneRaw[0] === "+" ? 1 : -1;
    const offsetHours = Number(zoneRaw.slice(1, 3));
    const offsetMinutes = Number(zoneRaw.slice(4, 6));
    if (offsetHours > 23 || offsetMinutes > 59) {
      reject("timestamp is invalid");
    }
    offsetMillis = sign * ((offsetHours * 60 + offsetMinutes) * 60_000);
  }
  return localMillis - offsetMillis;
}

function parseDateTime(value) {
  return parseIsoMillis(value, { requireTimezone: false });
}

function isSchemaDateTime(value) {
  if (typeof value !== "string") {
    return true;
  }
  try {
    parseIsoMillis(value, { requireTimezone: true });
    return true;
  } catch (error) {
    return false;
  }
}

function schemaFile(suiteBase, schemaName) {
  const filePath = path.join(suiteBase, "conformance", "vectors", "schemas", schemaName);
  if (!fs.existsSync(filePath)) {
    reject(`schema is missing: ${schemaName}`);
  }
  return filePath;
}

function schemaContext(suiteBase) {
  const key = path.resolve(suiteBase);
  const cached = schemaContexts.get(key);
  if (cached !== undefined) {
    return cached;
  }
  const ajv = new Ajv2020({
    allErrors: true,
    strict: false,
    validateFormats: true,
  });
  ajv.addFormat("date-time", {
    type: "string",
    validate: isSchemaDateTime,
  });
  ajv.addFormat("uri", true);
  const schemas = new Map();
  const validators = new Map();
  const schemaDir = path.join(suiteBase, "conformance", "vectors", "schemas");
  for (const name of fs.readdirSync(schemaDir)) {
    if (!name.endsWith(".json")) {
      continue;
    }
    const schema = readJson(path.join(schemaDir, name));
    schemas.set(name, schema);
    if (isObject(schema) && typeof schema.$id === "string") {
      ajv.addSchema(schema, schema.$id);
    }
  }
  const context = { ajv, schemas, validators };
  schemaContexts.set(key, context);
  return context;
}

function validateSchema(suiteBase, schemaName, data) {
  const context = schemaContext(suiteBase);
  const schema = context.schemas.get(schemaName) ?? readJson(schemaFile(suiteBase, schemaName));
  let validate = context.validators.get(schemaName);
  if (validate === undefined) {
    validate = typeof schema.$id === "string" ? context.ajv.getSchema(schema.$id) : undefined;
    if (validate === undefined) {
      validate = context.ajv.compile(schema);
    }
    context.validators.set(schemaName, validate);
  }
  if (!validate(data)) {
    reject("schema validation failed");
  }
}

function validateJsonSchemaObject(schema) {
  if (!isObject(schema)) {
    reject("constraint schema is not an object");
  }
  try {
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    ajv.validateSchema(schema);
    if (ajv.errors !== null) {
      reject("constraint schema is invalid");
    }
  } catch (error) {
    if (error instanceof Reject) {
      throw error;
    }
    reject("constraint schema is invalid");
  }
}

function validateAction(schema, action) {
  if (action == null) {
    return;
  }
  validateJsonSchemaObject(schema);
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  const validate = ajv.compile(schema);
  if (!validate(action)) {
    reject("action violates constraints");
  }
}

function resolveObject(name, inputData, context) {
  if (typeof name !== "string") {
    reject("object reference is not a string");
  }
  if (name === "input") {
    return inputData;
  }
  if (!name.startsWith("context.")) {
    reject("unsupported object reference");
  }
  let current = context;
  for (const part of name.slice("context.".length).split(".")) {
    if (!isObject(current) || !(part in current)) {
      reject("missing context object");
    }
    current = current[part];
  }
  return current;
}

function resolvePointer(root, pointer) {
  if (typeof pointer !== "string") {
    reject("JSON pointer is not a string");
  }
  if (pointer === "") {
    return root;
  }
  if (!pointer.startsWith("/")) {
    reject("invalid JSON pointer");
  }
  let current = root;
  for (const rawPart of pointer.split("/").slice(1)) {
    const part = rawPart.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(current)) {
      const index = Number(part);
      if (!Number.isInteger(index) || index < 0 || index >= current.length) {
        reject("JSON pointer is missing");
      }
      current = current[index];
    } else if (isObject(current)) {
      if (!(part in current)) {
        reject("JSON pointer is missing");
      }
      current = current[part];
    } else {
      reject("JSON pointer crosses a scalar");
    }
  }
  return current;
}

function resolveSide(side, inputData, context) {
  if (!isObject(side)) {
    reject("comparison side is not an object");
  }
  return resolvePointer(resolveObject(side.object, inputData, context), side.pointer);
}

function publicKeyObjectFromRaw(publicKeyB64url) {
  const publicKey = b64urlDecode(publicKeyB64url);
  if (publicKey.length !== 32) {
    reject("signature verification failed");
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
}

function privateKeyObjectFromSeed(seed) {
  if (seed.length !== 32) {
    reject("seed is not 32 bytes");
  }
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function rawPublicKeyFromPrivateKey(privateKey) {
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(publicDer).subarray(-32);
}

function verifyEd25519(publicKeyB64url, signatureB64url, payload) {
  try {
    const publicKey = publicKeyObjectFromRaw(publicKeyB64url);
    const signature = b64urlDecode(signatureB64url);
    if (!ed25519Verify(null, payload, publicKey, signature)) {
      reject("signature verification failed");
    }
  } catch (error) {
    if (error instanceof Reject) {
      throw error;
    }
    reject("signature verification failed");
  }
}

function hasReference(data, { relationship, allowedTypes = null, idValue = null }) {
  if (!isObject(data) || !Array.isArray(data.references)) {
    return false;
  }
  for (const reference of data.references) {
    if (!isObject(reference)) {
      continue;
    }
    if (reference.relationship !== relationship) {
      continue;
    }
    if (allowedTypes !== null && !allowedTypes.has(reference.type)) {
      continue;
    }
    if (idValue !== null && reference.id !== idValue) {
      continue;
    }
    return true;
  }
  return false;
}

function signatureEnvelope(inputData, algorithm) {
  if (!isObject(inputData)) {
    reject("input is not an object");
  }
  const signature = inputData.signature;
  if (!isObject(signature)) {
    reject("signature is missing");
  }
  if (signature.alg !== algorithm) {
    reject("signature algorithm is wrong");
  }
  return signature;
}

function signedPreimage(inputData, context, regression) {
  if (regression === "preimage-includes-signature") {
    if (
      isObject(inputData) &&
      isObject(context) &&
      Object.hasOwn(context, "signature_preimage_value")
    ) {
      const preimage = structuredClone(inputData);
      if (!isObject(preimage.signature)) {
        reject("signature is missing");
      }
      preimage.signature.value = context.signature_preimage_value;
      return jcsBytes(preimage);
    }
    return jcsBytes(inputData);
  }
  return jcsBytes(withoutTopLevel(inputData, new Set(["signature"])));
}

function stripSignaturesRecursive(value) {
  if (Array.isArray(value)) {
    return value.map((item) => stripSignaturesRecursive(item));
  }
  if (isObject(value)) {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      if (key !== "signature") {
        result[key] = stripSignaturesRecursive(item);
      }
    }
    return result;
  }
  return value;
}

function countersignPreimage(inputData) {
  return jcsBytes(stripSignaturesRecursive(withoutTopLevel(inputData, new Set(["countersignatures"]))));
}

function cosignPreimage(inputData) {
  return jcsBytes(stripSignaturesRecursive(inputData));
}

function bareSignature(inputData) {
  if (!isObject(inputData)) {
    reject("input is not an object");
  }
  if (typeof inputData.signature !== "string" || inputData.signature === "") {
    reject("signature is missing");
  }
  return inputData.signature;
}

function requireAlgorithm(inputData, algorithm) {
  if (!isObject(inputData)) {
    reject("input is not an object");
  }
  if (inputData.algorithm !== algorithm) {
    reject("signature algorithm is wrong");
  }
}

function ed25519DidKey(publicKeyBytes) {
  if (publicKeyBytes.length !== 32) {
    reject("Ed25519 public key is not 32 bytes");
  }
  return `did:key:z${b64urlEncode(Buffer.concat([Buffer.from([0xed, 0x01]), publicKeyBytes])).replace(
    /=+$/,
    "",
  )}`;
}

function publicKeyFromDidKey(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) {
    reject("counterparty DID is not did:key");
  }
  const decoded = b64urlDecode(did.slice("did:key:z".length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    reject("counterparty DID is not Ed25519 did:key");
  }
  return decoded.subarray(2);
}

function scopeRestrictionToSchema(scope) {
  if (!isObject(scope) || Object.keys(scope).length === 0) {
    reject("scope restriction is invalid");
  }
  const jsonSchemaKeys = new Set([
    "$schema",
    "$id",
    "$ref",
    "$defs",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "enum",
    "const",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "format",
  ]);
  if (Object.keys(scope).some((key) => jsonSchemaKeys.has(key))) {
    validateJsonSchemaObject(scope);
    return scope;
  }
  if (
    Object.keys(scope).length === 1 &&
    Object.hasOwn(scope, "max_spend") &&
    typeof scope.max_spend === "number"
  ) {
    return {
      type: "object",
      properties: {
        max_spend: { type: "number", maximum: scope.max_spend },
      },
    };
  }
  reject("scope restriction is unsupported");
}

function walkKeyStrings(value, pointer = "") {
  const items = [];
  if (isObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      const keyPointer = `${pointer}/${key.replace(/~/g, "~0").replace(/\//g, "~1")}`;
      items.push([keyPointer, key]);
      items.push(...walkKeyStrings(child, keyPointer));
    }
  } else if (Array.isArray(value)) {
    value.forEach((child, index) => {
      items.push(...walkKeyStrings(child, `${pointer}/${index}`));
    });
  } else if (typeof value === "string") {
    items.push([pointer, value]);
  }
  return items;
}

function containsRawTerm(inputData) {
  for (const [pointer, value] of walkKeyStrings(inputData)) {
    if (pointer === "/signature/value" || pointer.endsWith("/signature")) {
      continue;
    }
    if (pointer.startsWith("/countersignatures/")) {
      continue;
    }
    if (RAW_TERM_PATTERNS.some((pattern) => pattern.test(value))) {
      return true;
    }
  }
  return false;
}

function requireVectorShape(vector) {
  if (!isObject(vector)) {
    reject("vector is not an object");
  }
  for (const field of REQUIRED_VECTOR_FIELDS) {
    if (!Object.hasOwn(vector, field)) {
      reject("vector is missing required fields");
    }
  }
  if (vector.schema_version !== VECTOR_SCHEMA_VERSION) {
    reject("vector schema_version is unsupported");
  }
  if (typeof vector.id !== "string" || vector.id === "") {
    reject("vector id is invalid");
  }
  if (!RECORD_TYPES.has(vector.record_type)) {
    reject("record_type is unsupported");
  }
  if (!PROFILE_ORDER.has(vector.verification_profile)) {
    reject("verification_profile is unsupported");
  }
  if (vector.expected !== "accept" && vector.expected !== "reject") {
    reject("expected outcome is invalid");
  }
  if (!isObject(vector.context)) {
    reject("context is not an object");
  }
  return [vector.id, vector.input, vector.context, vector.verification_profile];
}

function verifyDecisionObject(inputData, context) {
  if (sha256Jcs(inputData) !== context.expected_decision_id) {
    reject("decision digest mismatch");
  }
}

function verifyOfferBinding(inputData, context) {
  const checks = context.checks;
  if (!Array.isArray(checks) || checks.length === 0) {
    reject("offer-binding checks are missing");
  }
  for (const check of checks) {
    if (!isObject(check)) {
      reject("offer-binding check is not an object");
    }
    if (check.kind === "jcs-sha256") {
      if (sha256Jcs(resolveObject(check.source, inputData, context)) !== check.expected) {
        reject("digest check failed");
      }
    } else if (check.kind === "jcs-sha256-pointer") {
      // Recompute a digest and compare it against a value carried inside the
      // artifact, rather than against a literal in the vector: a literal-only
      // check still passes when the artifact's own field has drifted away from
      // the data it claims to commit to.
      // Must match the `jcs-sha256-pointer` arm of verify_offer_binding in
      // conformance/reference-runner/runner.py and of the offer-binding
      // evaluator in scripts/conformance/generate_vectors.py.
      const source = resolveObject(check.source, inputData, context);
      const target = resolveSide(check.target, inputData, context);
      if (sha256Jcs(source) !== target) {
        reject("committed digest mismatch");
      }
    } else if (check.kind === "json-pointer-equal") {
      const left = resolveSide(check.left, inputData, context);
      const right = resolveSide(check.right, inputData, context);
      if (JSON.stringify(left) !== JSON.stringify(right)) {
        reject("binding check failed");
      }
    } else {
      reject("unknown offer-binding check kind");
    }
  }
}

function verifyReceipt(suiteBase, inputData, context, regression) {
  validateSchema(suiteBase, "approval_receipt.schema.json", inputData);
  if (
    !hasReference(inputData, {
      relationship: "approves",
      allowedTypes: new Set(["negotiation_session", "a2cn:negotiation_session"]),
    })
  ) {
    reject("approval reference is missing");
  }
  const signature = signatureEnvelope(inputData, "Ed25519");
  if (!isObject(context.public_keys_b64url)) {
    reject("issuer public key is missing");
  }
  verifyEd25519(
    context.public_keys_b64url.issuer,
    signature.value,
    signedPreimage(inputData, context, regression),
  );
  if (!isObject(inputData)) {
    reject("receipt input is not an object");
  }
  if (parseDateTime(inputData.expires_at) < parseDateTime(context.now)) {
    reject("receipt is expired");
  }
  if (!isObject(inputData.scope)) {
    reject("receipt scope is missing");
  }
  if (sha256Jcs(context.offer) !== inputData.scope.offer_hash) {
    reject("offer hash mismatch");
  }
}

function verifyRevocation(suiteBase, inputData, context, regression) {
  validateSchema(suiteBase, "revocation_record.schema.json", inputData);
  if (!isObject(inputData)) {
    reject("revocation input is not an object");
  }
  if (
    !hasReference(inputData, {
      relationship: "revokes",
      idValue: inputData.revoked_artifact_id,
    })
  ) {
    reject("revocation reference is missing");
  }
  const signature = signatureEnvelope(inputData, "EdDSA");
  if (!isObject(context.public_keys_b64url)) {
    reject("issuer public key is missing");
  }
  verifyEd25519(
    context.public_keys_b64url.issuer,
    signature.value,
    signedPreimage(inputData, context, regression),
  );
}

function cascadePreimage(inputData) {
  return jcsBytes(withoutTopLevel(inputData, new Set(["decision_id", "signature"])));
}

function verifyCascade(suiteBase, inputData, context, regression) {
  if (regression !== "schema-skipped") {
    validateSchema(suiteBase, "cascade_decision_record.schema.json", inputData);
  }
  if (!isObject(inputData)) {
    reject("cascade input is not an object");
  }
  const preimage = cascadePreimage(inputData);
  const claimedId = inputData.decision_id;
  if (typeof claimedId !== "string") {
    reject("decision_id is missing");
  }
  if (regression !== "decision-id-not-recomputed" && sha256Bytes(preimage) !== claimedId) {
    reject("decision_id mismatch");
  }
  if (context.expected_decision_id !== undefined && `sha256:${claimedId}` !== context.expected_decision_id) {
    reject("expected decision_id mismatch");
  }
  const signature = signatureEnvelope(inputData, "EdDSA");
  if (!isObject(context.public_keys_b64url)) {
    reject("issuer public key is missing");
  }
  const signaturePreimage =
    regression === "decision-id-not-recomputed"
      ? jcsBytes(withoutTopLevel(inputData, new Set(["signature"])))
      : preimage;
  verifyEd25519(context.public_keys_b64url.issuer, signature.value, signaturePreimage);
}

function verifyFulfillment(suiteBase, inputData, context, regression) {
  validateSchema(suiteBase, "fulfillment_attestation.schema.json", inputData);
  if (!isObject(inputData)) {
    reject("fulfillment input is not an object");
  }
  if (
    !hasReference(inputData, {
      relationship: "fulfills",
      idValue: inputData.agreement_attestation_id,
    })
  ) {
    reject("fulfillment reference is missing");
  }
  const signature = signatureEnvelope(inputData, "Ed25519");
  const preimage = signedPreimage(inputData, context, regression);
  verifyEd25519(context.public_key_b64url, signature.value, preimage);
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("canonical digest mismatch");
  }
  if (context.seed_ed25519_ascii !== undefined) {
    if (typeof context.seed_ed25519_ascii !== "string") {
      reject("seed is not a string");
    }
    const seedBytes = Buffer.from(context.seed_ed25519_ascii, "utf8");
    const privateKey = privateKeyObjectFromSeed(seedBytes);
    if (b64urlEncode(rawPublicKeyFromPrivateKey(privateKey)) !== context.public_key_b64url) {
      reject("seed public key mismatch");
    }
    if (context.signature_b64url !== undefined) {
      const derivedSignature = b64urlEncode(ed25519Sign(null, preimage, privateKey));
      if (derivedSignature !== context.signature_b64url || derivedSignature !== signature.value) {
        reject("seed signature mismatch");
      }
    }
  }
  const joinKeys = context.join_keys ?? {};
  if (!isObject(joinKeys)) {
    reject("join_keys is not an object");
  }
  if (Object.hasOwn(joinKeys, "charge_ref") && inputData.charge_ref !== joinKeys.charge_ref) {
    reject("charge_ref mismatch");
  }
  if (Object.hasOwn(joinKeys, "action_ref") && inputData.action_ref !== joinKeys.action_ref) {
    reject("action_ref mismatch");
  }
  if (context.forbid_raw_deal_terms && containsRawTerm(inputData)) {
    reject("raw deal terms are present");
  }
}

function verifyAttestation(suiteBase, inputData, context) {
  if (context.forbid_raw_deal_terms && containsRawTerm(inputData)) {
    reject("raw deal terms are present");
  }
  validateSchema(suiteBase, "attestation.schema.json", inputData);
  if (!isObject(inputData)) {
    reject("attestation input is not an object");
  }
  if (!isObject(context.public_keys_b64url)) {
    reject("attestation public keys are missing");
  }
  if (!Array.isArray(inputData.parties)) {
    reject("attestation parties are missing");
  }
  const verified = [];
  for (const party of inputData.parties) {
    if (!isObject(party)) {
      reject("attestation party is not an object");
    }
    const agentId = party.agent_id;
    if (typeof agentId !== "string" || agentId === "") {
      reject("attestation party agent_id is missing");
    }
    const publicKey = context.public_keys_b64url[agentId];
    if (typeof publicKey !== "string") {
      reject("attestation party public key is missing");
    }
    verifyEd25519(publicKey, bareSignature(party), jcsBytes(withoutTopLevel(party, new Set(["signature"]))));
    verified.push(agentId);
  }
  if (context.expected_verified_parties !== undefined) {
    if (
      !Array.isArray(context.expected_verified_parties) ||
      [...verified].sort().join("\u0000") !== [...context.expected_verified_parties].sort().join("\u0000")
    ) {
      reject("attestation verified party set mismatch");
    }
  }
}

function verifyAttestationCountersign(suiteBase, inputData, context) {
  validateSchema(suiteBase, "attestation.schema.json", inputData);
  if (!isObject(inputData)) {
    reject("attestation input is not an object");
  }
  if (
    !isObject(context.public_keys_b64url) ||
    !Array.isArray(context.countersigners) ||
    !isObject(inputData.countersignatures)
  ) {
    reject("attestation countersignature inputs are missing");
  }
  const preimage = countersignPreimage(inputData);
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("attestation countersignature digest mismatch");
  }
  for (const signer of context.countersigners) {
    if (typeof signer !== "string") {
      reject("countersigner is not a string");
    }
    const signature = inputData.countersignatures[signer];
    const publicKey = context.public_keys_b64url[signer];
    if (typeof signature !== "string" || typeof publicKey !== "string") {
      reject("countersignature or key is missing");
    }
    verifyEd25519(publicKey, signature, preimage);
  }
}

function verifyPredicate(suiteBase, inputData, context) {
  validateSchema(suiteBase, "predicate.json", inputData);
  if (!isObject(inputData)) {
    reject("predicate input is not an object");
  }
  requireAlgorithm(inputData, "EdDSA");
  const preimage = jcsBytes(withoutTopLevel(inputData, new Set(["signature"])));
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("predicate digest mismatch");
  }
  if (typeof context.public_key_b64url !== "string") {
    reject("predicate public key is missing");
  }
  verifyEd25519(context.public_key_b64url, bareSignature(inputData), preimage);
  if (inputData.status !== "active") {
    reject("predicate is not active");
  }
  if (parseDateTime(inputData.expires_at) < parseDateTime(context.now)) {
    reject("predicate is expired");
  }
}

function mandatePreimage(inputData) {
  return jcsBytes(withoutTopLevel(inputData, new Set(["signature"])));
}

function validateMandateCommon(suiteBase, inputData, context) {
  validateSchema(suiteBase, "mandate.schema.json", inputData);
  if (!isObject(inputData)) {
    reject("mandate input is not an object");
  }
  requireAlgorithm(inputData, "EdDSA");
  const preimage = mandatePreimage(inputData);
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("mandate digest mismatch");
  }
  if (typeof context.issuer_public_key_b64url !== "string") {
    reject("mandate issuer public key is missing");
  }
  verifyEd25519(context.issuer_public_key_b64url, bareSignature(inputData), preimage);
  if ((inputData.status ?? "active") !== "active") {
    reject("mandate is not active");
  }
  if (!isObject(inputData.validity)) {
    reject("mandate validity is missing");
  }
  const now = parseDateTime(context.now);
  if (inputData.validity.mode === "windowed") {
    if (parseDateTime(inputData.validity.not_before) > now) {
      reject("mandate is not yet valid");
    }
    if (parseDateTime(inputData.validity.not_after) < now) {
      reject("mandate is expired");
    }
  } else if (inputData.validity.mode === "sequence") {
    if (context.sequence_key !== inputData.validity.sequence_key) {
      reject("mandate sequence key mismatch");
    }
  } else if (inputData.validity.mode === "state_bound") {
    if (context.state_active !== true) {
      reject("mandate state is not active");
    }
  } else {
    reject("mandate validity mode is unsupported");
  }
  validateJsonSchemaObject(inputData.constraints);
  return inputData;
}

function verifyMandateProfile(suiteBase, inputData, context) {
  const mandate = validateMandateCommon(suiteBase, inputData, context);
  validateAction(mandate.constraints, context.action);
}

function verifyDelegationChainProfile(suiteBase, inputData, context) {
  const mandate = validateMandateCommon(suiteBase, inputData, context);
  const chain = mandate.delegation_chain;
  if (!Array.isArray(chain) || chain.length === 0) {
    reject("delegation chain is missing");
  }
  if (!isObject(context.delegation_public_keys_b64url)) {
    reject("delegation public keys are missing");
  }
  if (!isObject(chain[0]) || chain[0].delegator !== mandate.issuer) {
    reject("delegation chain root mismatch");
  }
  if (!isObject(chain[chain.length - 1]) || chain[chain.length - 1].delegate !== mandate.subject) {
    reject("delegation chain tail mismatch");
  }
  const effectiveConstraints = [mandate.constraints];
  let previousDelegate = null;
  for (const link of chain) {
    if (!isObject(link)) {
      reject("delegation link is not an object");
    }
    if (previousDelegate !== null && link.delegator !== previousDelegate) {
      reject("delegation chain continuity mismatch");
    }
    if (typeof link.delegator !== "string") {
      reject("delegation link delegator is missing");
    }
    const publicKey = context.delegation_public_keys_b64url[link.delegator];
    if (typeof publicKey !== "string") {
      reject("delegation link public key is missing");
    }
    requireAlgorithm(link, "EdDSA");
    verifyEd25519(publicKey, bareSignature(link), jcsBytes(withoutTopLevel(link, new Set(["signature"]))));
    if (Object.hasOwn(link, "scope_restriction")) {
      effectiveConstraints.push(scopeRestrictionToSchema(link.scope_restriction));
    }
    previousDelegate = link.delegate;
  }
  validateAction(
    effectiveConstraints.length === 1 ? effectiveConstraints[0] : { allOf: effectiveConstraints },
    context.action,
  );
}

function verifyCosign(inputData, context) {
  if (!isObject(inputData)) {
    reject("cosign input is not an object");
  }
  if (
    typeof context.counterparty_did !== "string" ||
    typeof context.publisher_did !== "string" ||
    typeof context.counterparty_public_key_b64url !== "string"
  ) {
    reject("cosign context is missing");
  }
  if (context.counterparty_did === context.publisher_did) {
    reject("counterparty DID equals publisher DID");
  }
  const publicKey = b64urlDecode(context.counterparty_public_key_b64url);
  if (ed25519DidKey(publicKey) !== context.counterparty_did) {
    reject("did:key derivation mismatch");
  }
  if (!publicKeyFromDidKey(context.counterparty_did).equals(publicKey)) {
    reject("did:key decoding mismatch");
  }
  if (!Array.isArray(inputData.parties)) {
    reject("cosign parties are missing");
  }
  const matches = inputData.parties.filter(
    (party) => isObject(party) && party.agent_id === context.counterparty_did,
  );
  if (matches.length !== 1) {
    reject("counterparty party entry is not unique");
  }
  const preimage = cosignPreimage(inputData);
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("cosign digest mismatch");
  }
  verifyEd25519(context.counterparty_public_key_b64url, bareSignature(matches[0]), preimage);
}

function verifyBareSignedSchemaObject(suiteBase, inputData, context, schemaName) {
  validateSchema(suiteBase, schemaName, inputData);
  requireAlgorithm(inputData, "EdDSA");
  const preimage = jcsBytes(withoutTopLevel(inputData, new Set(["signature"])));
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("canonical digest mismatch");
  }
  if (typeof context.public_key_b64url !== "string") {
    reject("public key is missing");
  }
  verifyEd25519(context.public_key_b64url, bareSignature(inputData), preimage);
}

function verifyDigestChecks(inputData, context) {
  const checks = context.digest_checks ?? [];
  if (!Array.isArray(checks)) {
    reject("digest checks are not a list");
  }
  for (const check of checks) {
    if (!isObject(check)) {
      reject("digest check is not an object");
    }
    if (check.kind !== "jcs-sha256-pointer") {
      reject("unknown digest check kind");
    }
    const source = resolveObject(check.source, inputData, context);
    const target = resolveSide(check.target, inputData, context);
    if (sha256Jcs(source) !== target) {
      reject("committed digest mismatch");
    }
  }
}

function verifyClosurePredicate(suiteBase, inputData, context) {
  validateSchema(suiteBase, "closure_predicate.schema.json", inputData);
  const preimage = jcsBytes(withoutTopLevel(inputData, new Set(["signature"])));
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("closure predicate digest mismatch");
  }
  verifyDigestChecks(inputData, context);
}

function verifyChainSession(suiteBase, inputData, context) {
  validateSchema(suiteBase, "chain_session.schema.json", inputData);
  if (context.canonical_sha256 !== undefined && sha256Jcs(inputData) !== context.canonical_sha256) {
    reject("chain session digest mismatch");
  }
}

function transitionPreconditionsHold(initialSession, targetState, transitionNow) {
  const sourceState = initialSession.state;
  if (sourceState === "PROPOSED" && targetState === "OPEN") {
    return (
      Array.isArray(initialSession.commitments) &&
      Array.isArray(initialSession.participants) &&
      initialSession.commitments.length === initialSession.participants.length
    );
  }
  if (sourceState === "OPEN" && targetState === "ACTIVATED") {
    return (
      typeof initialSession.activation_proof_id === "string" &&
      transitionNow < parseDateTime(initialSession.activation_deadline)
    );
  }
  if (sourceState === "OPEN" && targetState === "DISSOLVED") {
    return typeof initialSession.unwind_record_id === "string";
  }
  if (sourceState === "OPEN" && targetState === "EXPIRED") {
    return (
      transitionNow >= parseDateTime(initialSession.activation_deadline) &&
      initialSession.activation_proof_id == null
    );
  }
  return true;
}

function verifyChainSessionTransition(suiteBase, inputData) {
  if (!isObject(inputData)) {
    reject("transition input is not an object");
  }
  if (
    !isObject(inputData.initial_session) ||
    typeof inputData.attempt_transition !== "string" ||
    typeof inputData.transition_now !== "string"
  ) {
    reject("transition input is malformed");
  }
  validateSchema(suiteBase, "chain_session.schema.json", inputData.initial_session);
  const transitionNow = parseDateTime(inputData.transition_now);
  const sourceState = inputData.initial_session.state;
  if (typeof sourceState !== "string") {
    reject("transition source state is missing");
  }
  const targets = LEGAL_CHAIN_TRANSITIONS.get(sourceState) ?? new Set();
  if (!targets.has(inputData.attempt_transition)) {
    reject("transition is not legal");
  }
  if (!transitionPreconditionsHold(inputData.initial_session, inputData.attempt_transition, transitionNow)) {
    reject("transition preconditions failed");
  }
}

function requireObject(value, label) {
  if (!isObject(value)) {
    reject(`${label} is not an object`);
  }
  return value;
}

function profileSubdict(payload, allowed, { allowExtra = false, dropNone = false } = {}) {
  if (!allowExtra && Object.keys(payload).some((key) => !allowed.has(key))) {
    reject("agent profile contains an unknown signed-form key");
  }
  const result = {};
  for (const key of [...allowed].sort()) {
    if (Object.hasOwn(payload, key)) {
      result[key] = payload[key];
    }
  }
  if (dropNone) {
    for (const key of Object.keys(result)) {
      if (result[key] === null) {
        delete result[key];
      }
    }
  }
  return result;
}

function agentProfileCanonical(inputData) {
  const profile = requireObject(inputData, "agent profile");
  if (Object.keys(profile).some((key) => !AGENT_PROFILE_TOP_LEVEL_FIELDS.has(key))) {
    reject("agent profile top-level key is unknown");
  }
  const capabilities = profileSubdict(
    requireObject(profile.capabilities, "agent profile capabilities"),
    AGENT_PROFILE_CAPABILITY_FIELDS,
  );
  const negotiationProfile = profileSubdict(
    requireObject(profile.negotiation_profile, "agent profile negotiation_profile"),
    AGENT_PROFILE_NEGOTIATION_FIELDS,
  );
  const trustSignals = profileSubdict(
    requireObject(profile.trust_signals, "agent profile trust_signals"),
    AGENT_PROFILE_TRUST_SIGNAL_FIELDS,
    { allowExtra: true, dropNone: true },
  );
  if (Object.hasOwn(trustSignals, "sovereignty")) {
    trustSignals.sovereignty = profileSubdict(
      requireObject(trustSignals.sovereignty, "agent profile sovereignty"),
      AGENT_PROFILE_SOVEREIGNTY_FIELDS,
    );
  }
  if (Object.hasOwn(trustSignals, "reputation")) {
    if (!Array.isArray(trustSignals.reputation)) {
      reject("agent profile reputation is not a list");
    }
    trustSignals.reputation = trustSignals.reputation.map((assertion) => {
      const normalized = profileSubdict(
        requireObject(assertion, "agent profile reputation assertion"),
        AGENT_PROFILE_REPUTATION_FIELDS,
        { allowExtra: true, dropNone: true },
      );
      if (!Object.hasOwn(normalized, "provider")) {
        reject("agent profile reputation assertion is missing provider");
      }
      return normalized;
    });
  }
  const endpoints = profileSubdict(
    requireObject(profile.endpoints, "agent profile endpoints"),
    AGENT_PROFILE_ENDPOINT_FIELDS,
    { dropNone: true },
  );
  const location = profileSubdict(
    requireObject(profile.location, "agent profile location"),
    AGENT_PROFILE_LOCATION_FIELDS,
  );
  const canonical = {};
  for (const fieldName of AGENT_PROFILE_CANONICAL_FIELDS) {
    if (fieldName === "capabilities") {
      canonical[fieldName] = capabilities;
    } else if (fieldName === "negotiation_profile") {
      canonical[fieldName] = negotiationProfile;
    } else if (fieldName === "trust_signals") {
      canonical[fieldName] = trustSignals;
    } else if (fieldName === "endpoints") {
      canonical[fieldName] = endpoints;
    } else if (fieldName === "location") {
      canonical[fieldName] = location;
    } else if (Object.hasOwn(profile, fieldName)) {
      canonical[fieldName] = profile[fieldName];
    } else {
      reject("agent profile signed canonical field is missing");
    }
  }
  return canonical;
}

function verifyAgentProfile(inputData, context) {
  if (
    !Array.isArray(context.canonical_fields) ||
    context.canonical_fields.length !== AGENT_PROFILE_CANONICAL_FIELDS.length ||
    !context.canonical_fields.every((field, index) => field === AGENT_PROFILE_CANONICAL_FIELDS[index])
  ) {
    reject("agent profile canonical field list is wrong");
  }
  const profile = requireObject(inputData, "agent profile");
  const preimage = jcsBytes(agentProfileCanonical(profile));
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("agent profile canonical digest mismatch");
  }
  verifyEd25519(context.public_key_b64url, profile.signature, preimage);
}

function verifyReceiptBundle(suiteBase, inputData, context) {
  validateSchema(suiteBase, "receipt_bundle.schema.json", inputData);
  const signable = withoutTopLevel(inputData, new Set(["agent_signature", "concordia_receipt_bundle"]));
  const preimage = jcsBytes(signable);
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("receipt bundle canonical digest mismatch");
  }
  const bundle = requireObject(inputData, "receipt bundle");
  verifyEd25519(context.public_key_b64url, bundle.agent_signature, preimage);
}

function verifyMerkleProof(attestationId, proof, root) {
  if (root === "") {
    return false;
  }
  let currentHash = sha256Bytes(Buffer.from(attestationId, "utf8"));
  let index = proof.index ?? 0;
  const proofHashes = proof.proof ?? [];
  if (!Number.isInteger(index) || !Array.isArray(proofHashes)) {
    return false;
  }
  for (const siblingHash of proofHashes) {
    if (typeof siblingHash !== "string") {
      return false;
    }
    const combined = index % 2 === 0 ? currentHash + siblingHash : siblingHash + currentHash;
    currentHash = sha256Bytes(Buffer.from(combined, "utf8"));
    index = Math.trunc(index / 2);
  }
  return currentHash === root;
}

function verifyCompetenceProof(inputData, context) {
  const proof = requireObject(inputData, "competence proof");
  const required = new Set([
    "proof_id",
    "agent_id",
    "created_at",
    "claims",
    "attestation_merkle_root",
    "attestation_count",
    "merkle_proofs",
    "revealed_attestations",
    "agent_signature",
  ]);
  if ([...required].some((key) => !Object.hasOwn(proof, key))) {
    reject("competence proof is missing a required field");
  }
  const claims = requireObject(proof.claims, "competence proof claims");
  if (claims.total_negotiations !== proof.attestation_count) {
    reject("competence proof attestation count mismatch");
  }
  if (
    typeof proof.attestation_merkle_root !== "string" ||
    !Array.isArray(proof.merkle_proofs) ||
    !Array.isArray(proof.revealed_attestations)
  ) {
    reject("competence proof Merkle fields are malformed");
  }
  const proofsByAttestationId = new Map();
  for (const item of proof.merkle_proofs) {
    const proofItem = requireObject(item, "competence proof Merkle proof");
    if (typeof proofItem.attestation_id !== "string") {
      reject("competence proof Merkle proof has no attestation_id");
    }
    proofsByAttestationId.set(proofItem.attestation_id, proofItem);
  }
  for (const item of proof.revealed_attestations) {
    const attestation = requireObject(item, "competence proof revealed attestation");
    if (typeof attestation.attestation_id !== "string") {
      reject("revealed attestation has no attestation_id");
    }
    const maybeProof = proofsByAttestationId.get(attestation.attestation_id);
    if (
      maybeProof === undefined ||
      !verifyMerkleProof(attestation.attestation_id, maybeProof, proof.attestation_merkle_root)
    ) {
      reject("competence proof Merkle inclusion failed");
    }
  }
  const signable = withoutTopLevel(proof, new Set(["agent_signature", "concordia_competence_proof"]));
  const preimage = jcsBytes(signable);
  if (context.canonical_sha256 !== undefined && canonicalSha256(preimage) !== context.canonical_sha256) {
    reject("competence proof canonical digest mismatch");
  }
  verifyEd25519(context.public_key_b64url, proof.agent_signature, preimage);
}

function messageHash(message) {
  return sha256Jcs(message);
}

function attestationVersionAtLeast(value, major, minor) {
  if (typeof value !== "string" || !SEMVER_RE.test(value)) {
    return false;
  }
  const [actualMajor, actualMinor] = value.split(".").map((item) => Number(item));
  return actualMajor > major || (actualMajor === major && actualMinor >= minor);
}

function verifyMessageChainReceiptBinding(suiteBase, inputData, messages, context) {
  if (!Object.hasOwn(inputData, "receipt")) {
    return;
  }
  const receipt = requireObject(inputData.receipt, "message chain receipt");
  validateSchema(suiteBase, "attestation.schema.json", receipt);
  if (!attestationVersionAtLeast(receipt.concordia_attestation, 0, 3)) {
    reject("receipt is legacy set-unbound");
  }
  if (typeof receipt.chain_head !== "string" || !SHA256_HEX_RE.test(receipt.chain_head)) {
    reject("receipt chain_head is malformed");
  }
  if (
    !Number.isInteger(receipt.message_count) ||
    typeof receipt.message_count === "boolean" ||
    receipt.message_count < 1
  ) {
    reject("receipt message_count is malformed");
  }
  if (!isObject(context.public_keys_b64url)) {
    reject("receipt public key map is missing");
  }
  if (!Array.isArray(receipt.parties)) {
    reject("receipt parties are missing");
  }
  if (!isObject(receipt.countersignatures)) {
    reject("receipt countersignatures are missing");
  }
  const countersignPayload = countersignPreimage(receipt);
  for (const partyItem of receipt.parties) {
    const party = requireObject(partyItem, "receipt party");
    if (typeof party.agent_id !== "string" || party.agent_id === "") {
      reject("receipt party agent_id is missing");
    }
    const publicKey = context.public_keys_b64url[party.agent_id];
    if (typeof publicKey !== "string") {
      reject("receipt party public key is missing");
    }
    verifyEd25519(
      publicKey,
      bareSignature(party),
      jcsBytes(withoutTopLevel(party, new Set(["signature"]))),
    );
    const countersignature = receipt.countersignatures[party.agent_id];
    if (typeof countersignature !== "string") {
      reject("receipt countersignature is missing");
    }
    verifyEd25519(publicKey, countersignature, countersignPayload);
  }
  if (receipt.message_count !== messages.length) {
    reject("receipt message_count mismatch");
  }
  if (receipt.chain_head !== messageHash(messages[messages.length - 1])) {
    reject("receipt chain_head mismatch");
  }
}

function verifyMessageChain(suiteBase, inputData, context, regression) {
  const chain = requireObject(inputData, "message chain");
  const chainKeys = Object.keys(chain).sort().join("\u0000");
  if (chainKeys !== "messages" && chainKeys !== "messages\u0000receipt") {
    reject("message chain input must only contain messages or messages plus receipt");
  }
  const messages = chain.messages;
  if (!Array.isArray(messages) || messages.length === 0) {
    reject("message chain messages are missing");
  }
  if (context.expected_message_count !== undefined && context.expected_message_count !== messages.length) {
    reject("message chain count mismatch");
  }
  for (const item of messages) {
    requireObject(item, "message chain message");
  }
  if (regression !== "skip-linkage-walk") {
    if (messages[0].prev_hash !== GENESIS_HASH) {
      reject("message chain first prev_hash is not genesis");
    }
    for (let index = 1; index < messages.length; index += 1) {
      if (messages[index].prev_hash !== messageHash(messages[index - 1])) {
        reject("message chain prev_hash mismatch");
      }
    }
  }
  if (!isObject(context.public_keys_b64url)) {
    reject("message chain public key map is missing");
  }
  for (const item of messages) {
    const message = requireObject(item, "message chain message");
    const sender = requireObject(message.from, "message chain sender");
    if (typeof sender.agent_id !== "string") {
      reject("message chain sender agent_id is missing");
    }
    verifyEd25519(
      context.public_keys_b64url[sender.agent_id],
      message.signature,
      jcsBytes(withoutTopLevel(message, new Set(["signature"]))),
    );
  }
  if (context.expected_message_hashes !== undefined) {
    const actualHashes = messages.map((message) => messageHash(message));
    if (
      !Array.isArray(context.expected_message_hashes) ||
      context.expected_message_hashes.length !== actualHashes.length ||
      !context.expected_message_hashes.every((item, index) => item === actualHashes[index])
    ) {
      reject("message chain hash list mismatch");
    }
  }
  if (regression !== "receipt-set-unchecked") {
    verifyMessageChainReceiptBinding(suiteBase, chain, messages, context);
  }
}

function verifyProfile(suiteBase, profile, inputData, context, regression) {
  if (profile === "decision-object-v1") {
    verifyDecisionObject(inputData, context);
  } else if (profile === "offer-binding-v1") {
    verifyOfferBinding(inputData, context);
  } else if (profile === "receipt-v1") {
    verifyReceipt(suiteBase, inputData, context, regression);
  } else if (profile === "revocation-v1") {
    verifyRevocation(suiteBase, inputData, context, regression);
  } else if (profile === "cascade-decision-v1") {
    verifyCascade(suiteBase, inputData, context, regression);
  } else if (profile === "fulfillment-attestation-v1") {
    verifyFulfillment(suiteBase, inputData, context, regression);
  } else if (profile === "attestation-v1") {
    verifyAttestation(suiteBase, inputData, context);
  } else if (profile === "attestation-countersign-v1") {
    verifyAttestationCountersign(suiteBase, inputData, context);
  } else if (profile === "predicate-v1") {
    verifyPredicate(suiteBase, inputData, context);
  } else if (profile === "mandate-v1") {
    verifyMandateProfile(suiteBase, inputData, context);
  } else if (profile === "delegation-chain-v1") {
    verifyDelegationChainProfile(suiteBase, inputData, context);
  } else if (profile === "cosign-v1") {
    verifyCosign(inputData, context);
  } else if (profile === "conditional-commitment-v1") {
    verifyBareSignedSchemaObject(suiteBase, inputData, context, "conditional_commitment.schema.json");
  } else if (profile === "atomic-activation-proof-v1") {
    verifyBareSignedSchemaObject(suiteBase, inputData, context, "atomic_activation_proof.schema.json");
  } else if (profile === "unwind-record-v1") {
    verifyBareSignedSchemaObject(suiteBase, inputData, context, "unwind_record.schema.json");
  } else if (profile === "closure-predicate-v1") {
    verifyClosurePredicate(suiteBase, inputData, context);
  } else if (profile === "chain-session-v1") {
    verifyChainSession(suiteBase, inputData, context);
  } else if (profile === "chain-session-transition-v1") {
    verifyChainSessionTransition(suiteBase, inputData);
  } else if (profile === "agent-profile-v1") {
    verifyAgentProfile(inputData, context);
  } else if (profile === "competence-proof-v1") {
    verifyCompetenceProof(inputData, context);
  } else if (profile === "receipt-bundle-v1") {
    verifyReceiptBundle(suiteBase, inputData, context);
  } else if (profile === "message-chain-v1") {
    verifyMessageChain(suiteBase, inputData, context, regression);
  } else {
    reject("unknown verification profile");
  }
}

function evaluateVector(suiteBase, vector, regression) {
  try {
    const [, inputData, context, profile] = requireVectorShape(vector);
    verifyProfile(suiteBase, profile, inputData, context, regression);
  } catch (error) {
    if (error instanceof Reject) {
      return "reject";
    }
    return "reject";
  }
  return "accept";
}

function suiteBaseFromRoot(suiteRoot) {
  if (path.basename(suiteRoot) === "vectors" && path.basename(path.dirname(suiteRoot)) === "conformance") {
    return path.dirname(path.dirname(suiteRoot));
  }
  return suiteRoot;
}

function manifestPathFromArg(pathArg) {
  const suiteRoot = path.resolve(pathArg);
  const stats = fs.statSync(suiteRoot);
  const manifestPath = stats.isDirectory() ? path.join(suiteRoot, "manifest.json") : suiteRoot;
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`manifest not found: ${manifestPath}`);
  }
  return [manifestPath, suiteBaseFromRoot(path.dirname(manifestPath))];
}

function resolveManifestFile(suiteBase, relPath) {
  const filePath = path.join(suiteBase, relPath);
  if (!fs.existsSync(filePath)) {
    throw new Error(`manifest file not found: ${relPath}`);
  }
  return filePath;
}

function activeRegression() {
  const raw = process.env.RUNNER_REGRESS;
  if (raw === undefined) {
    return null;
  }
  if (process.env.CONCORDIA_CONFORMANCE_TEST_REGRESS !== "1") {
    throw new Error("RUNNER_REGRESS is test-only; set CONCORDIA_CONFORMANCE_TEST_REGRESS=1");
  }
  const allowed = new Set([
    "preimage-includes-signature",
    "schema-skipped",
    "decision-id-not-recomputed",
    "skip-linkage-walk",
    "receipt-set-unchecked",
  ]);
  if (!allowed.has(raw)) {
    throw new Error(`unknown RUNNER_REGRESS value: ${raw}`);
  }
  return raw;
}

function runSuite(suiteArg, regression) {
  const [manifestPath, suiteBase] = manifestPathFromArg(suiteArg);
  const manifest = readJson(manifestPath);
  if (!isObject(manifest)) {
    console.log("[FAIL] manifest expected=object got=reject");
    return 1;
  }
  if (!isObject(manifest.files)) {
    console.log("[FAIL] manifest.files expected=object got=reject");
    return 1;
  }
  const totals = { positive: 0, mutation: 0, canary: 0 };
  let failures = 0;
  for (const section of ["positive", "mutation", "canary"]) {
    const sectionFiles = manifest.files[section];
    if (!Array.isArray(sectionFiles)) {
      console.log(`[FAIL] manifest.files.${section} expected=list got=reject`);
      failures += 1;
      continue;
    }
    for (const relPath of sectionFiles) {
      totals[section] += 1;
      let vectorId = String(relPath);
      let expected = "<unreadable>";
      let got = "reject";
      try {
        if (typeof relPath !== "string") {
          reject("manifest path is not a string");
        }
        const vector = readJson(resolveManifestFile(suiteBase, relPath));
        if (isObject(vector) && typeof vector.id === "string") {
          vectorId = vector.id;
          expected = vector.expected ?? "<missing>";
        }
        got = evaluateVector(suiteBase, vector, regression);
      } catch (error) {
        got = "reject";
      }
      if (expected === got) {
        console.log(`[OK] ${vectorId}`);
      } else {
        failures += 1;
        console.log(`[FAIL] ${vectorId} expected=${expected} got=${got}`);
      }
    }
  }
  const executed = totals.positive + totals.mutation + totals.canary;
  console.log(
    `[SUMMARY] positive=${totals.positive} mutation=${totals.mutation} canary=${totals.canary} ok=${
      executed - failures
    } fail=${failures}`,
  );
  if (executed === 0) {
    console.log("[FAIL] zero vectors executed");
    return 1;
  }
  return failures === 0 ? 0 : 1;
}

function main(argv) {
  if (argv.length !== 1) {
    console.error("usage: runner.mjs <path to conformance/vectors/ or manifest.json>");
    return 2;
  }
  return runSuite(argv[0], activeRegression());
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
