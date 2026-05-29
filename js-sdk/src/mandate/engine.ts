/**
 * Concordia mandate verification + signing ENGINE.
 *
 * Port of `concordia/mandate.py` (the engine layer). Builds on the merged
 * mandate-MODELS layer (`src/mandate/mandate.ts`, PR 5) and the merged Ed25519
 * crypto layer (`src/crypto/signing.ts`). A mandate is a signed credential
 * authorizing an agent to act within constraints; this module signs them and
 * verifies them against the five Python checks: issuer signature, validity
 * window, constraint-schema compliance, delegation-chain integrity, and
 * revocation status.
 *
 * Cross-language parity is the load-bearing property, asserted against fixtures
 * generated FROM Python (`tests/fixtures/mandate/mandate_engine_vectors.json`):
 *   1. Signature bytes. `signMandate` / `signDelegation` reuse the merged
 *      Ed25519 `sign()` over the SAME canonical payload Python signs (the
 *      mandate/link `to_dict()` minus `signature`), so the base64url signature
 *      is byte-identical to Python `sign_mandate` / `sign_delegation`.
 *   2. Schema-validation accept/reject AND error text. Python's
 *      `validate_mandate_schema` runs CPython `jsonschema.validate` and returns
 *      a `"Schema: <message>"` list. The TS engine drives `ajv` (already a
 *      dependency) and TRANSLATES ajv's structured error into CPython
 *      jsonschema's message templates (see {@link pythonJsonschemaMessage}), so
 *      the strings match byte-for-byte. CRITICAL: CPython `jsonschema.validate`
 *      does NOT assert `format` by default (a bad `date-time` / `uri` PASSES),
 *      so ajv runs with `validateFormats: false` to match — a format-asserting
 *      validator would be a fail-CLOSED divergence (reject what Python accepts).
 *   3. `validate_constraints` / `compose_effective_constraints` /
 *      `check_temporal_validity` / `verify_delegation_chain` / `verifyMandate`
 *      outcomes (boolean checks, `failure_reason`, error lists) match Python.
 *
 * DEFERRED — revocation network I/O (documented + boundary fixture + skipped
 * test, mirroring the predicate `cmpc` revocation defer):
 *   Python `verify_mandate` calls `check_revocation` (a `urllib` GET against
 *   `mandate.revocation_endpoint`) when `check_revocation_status` is true and an
 *   endpoint is set. The network fetch is NOT ported in this PR. Instead
 *   {@link verifyMandate} accepts an injectable `revocationChecker` hook. With
 *   NO hook injected:
 *     - `checkRevocationStatus: false` (default) reproduces Python's
 *       "endpoint not checked" outcome exactly (the no-revocation result the
 *       fixtures assert).
 *     - `checkRevocationStatus: true` + an endpoint set + no hook is the
 *       deferred network path: the engine throws
 *       {@link MandateValidationError} rather than silently passing (no
 *       fail-open). A future PR ports the `urllib` fetch into a default hook.
 *   The boundary is pinned by `deferred_revocation_case` in the fixture + an
 *   `it.skip` test documenting the expected outcome once the fetch lands.
 *
 * ES256 — DEFERRED (matches the merged crypto layer, which is EdDSA-only).
 *   Python's `sign_mandate` / `verify_delegation_chain` dispatch on `algorithm`
 *   and support `ES256` via an `ES256KeyPair`. The merged `sign()` / `verify()`
 *   are Ed25519-only, so this engine signs/verifies EdDSA and throws a clear
 *   {@link MandateValidationError} for `ES256`, rather than half-implementing a
 *   second curve. ES256 lands when the crypto layer ports it.
 */

import Ajv2020, { type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import { sign, verify, KeyPair } from '../crypto/signing.js';
import {
  type Mandate,
  type DelegationLink,
  type ValidityWindow,
  type MandateVerificationResult,
  TemporalMode,
  MandateStatus,
  MANDATE_JSON_SCHEMA,
  MandateValidationError,
  mandateToDict,
  mandateFromDict,
  delegationLinkToDict,
  makeMandateVerificationResult,
} from './mandate.js';

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

/**
 * Sign a mandate with Ed25519, returning a copy with `signature` set. Mirrors
 * Python `sign_mandate`: signs over the mandate `to_dict()` with `signature`
 * removed, using the mandate's `algorithm`.
 *
 * The merged `sign()` strips a top-level `signature` and canonicalizes, which
 * is the exact signing input Python uses (`{k: v for ... if k != "signature"}`
 * -> `canonical_json`). ES256 is deferred (throws), matching the EdDSA-only
 * crypto layer.
 */
export function signMandate(mandate: Mandate, keyPair: KeyPair): Mandate {
  assertEdDSA(mandate.algorithm);
  const mandateDict = mandateToDict(mandate);
  delete mandateDict.signature;
  const signature = sign(mandateDict, keyPair);
  return { ...mandate, signature };
}

/**
 * Sign a delegation link with Ed25519, returning a copy with `signature` set.
 * Mirrors Python `sign_delegation`: signs over the link `to_dict()` with
 * `signature` removed, using the link's `algorithm` (default `EdDSA`).
 */
export function signDelegation(
  link: DelegationLink,
  keyPair: KeyPair,
): DelegationLink {
  assertEdDSA(link.algorithm ?? 'EdDSA');
  const linkDict = delegationLinkToDict(link);
  delete linkDict.signature;
  const signature = sign(linkDict, keyPair);
  return { ...link, signature };
}

/**
 * Guard mirroring the crypto layer's EdDSA-only scope. Python `sign_message`
 * dispatches on `alg` and supports `ES256`; the merged TS `sign()` is
 * Ed25519-only, so `ES256` is rejected here rather than silently mis-signed.
 */
function assertEdDSA(algorithm: string): void {
  if (algorithm === 'ES256') {
    throw new MandateValidationError(
      'ES256 mandate signing is not yet ported (the crypto layer is EdDSA-only); deferred',
    );
  }
  if (algorithm !== 'EdDSA') {
    throw new MandateValidationError(`Unsupported algorithm: ${algorithm}`);
  }
}

// ---------------------------------------------------------------------------
// Schema validation (ajv driven, CPython jsonschema message parity)
// ---------------------------------------------------------------------------

// `validateFormats: false` is load-bearing: CPython `jsonschema.validate` does
// NOT assert `format` by default, so a bad `date-time`/`uri` PASSES there. ajv
// asserts formats by default; turning it off keeps accept/reject parity (and
// avoids a fail-closed divergence). `strict: false` mirrors jsonschema's
// non-strict keyword handling (`default`, annotations, etc. are ignored, not
// errors).
const ajv = new Ajv2020({
  allErrors: false,
  strict: false,
  validateFormats: false,
});

const mandateValidator: ValidateFunction = ajv.compile(MANDATE_JSON_SCHEMA);

/**
 * Validate a mandate dict against {@link MANDATE_JSON_SCHEMA}. Mirrors Python
 * `validate_mandate_schema`: returns a list of error messages (empty if valid).
 * On a violation, returns a single-element `["Schema: <message>"]` where
 * `<message>` is CPython jsonschema's message for the first/best-match error,
 * reconstructed from ajv's structured error by {@link pythonJsonschemaMessage}.
 */
export function validateMandateSchema(
  mandateDict: Record<string, unknown>,
): string[] {
  const ok = mandateValidator(mandateDict);
  if (ok) {
    return [];
  }
  const errors = mandateValidator.errors ?? [];
  if (errors.length === 0) {
    return [];
  }
  const message = pythonJsonschemaMessage(
    selectError(errors),
    mandateDict,
    MANDATE_JSON_SCHEMA as Record<string, unknown>,
  );
  return [`Schema: ${message}`];
}

/**
 * Pick the single error CPython jsonschema would surface. CPython's
 * `validate()` raises the "best match" error; with ajv's `allErrors: false`
 * the first reported error is generally the same selection (verified against
 * the Python-generated fixtures, which capture CPython's actual choice for
 * every case). This indirection is the seam where a future ordering divergence
 * would be handled.
 */
function selectError(errors: ErrorObject[]): ErrorObject {
  // Callers only invoke this after confirming `errors.length > 0`.
  return errors[0] as ErrorObject;
}

/** Resolve the instance value an ajv error points at (via its `instancePath`). */
function instanceAt(
  error: ErrorObject,
  root: Record<string, unknown>,
): unknown {
  const path = error.instancePath;
  if (path === '' || path === undefined) {
    return root;
  }
  // ajv instancePath is a JSON Pointer ("/a/0/b"); walk it. `~1`/`~0` are the
  // escaped `/` and `~` per RFC 6901.
  const tokens = path
    .split('/')
    .slice(1)
    .map((t) => t.replace(/~1/g, '/').replace(/~0/g, '~'));
  let current: unknown = root;
  for (const token of tokens) {
    if (Array.isArray(current)) {
      current = current[Number(token)];
    } else if (current !== null && typeof current === 'object') {
      current = (current as Record<string, unknown>)[token];
    } else {
      return undefined;
    }
  }
  return current;
}

/**
 * Reconstruct CPython jsonschema's validation message for an ajv error.
 *
 * CPython jsonschema renders one message per failing keyword; the templates are
 * stable across jsonschema 4.x (verified on 3.9/4.25.1 and 3.12/4.26.0). Every
 * instance value embedded in a message uses CPython `repr()` (e.g. `'x'`, `{}`,
 * `{'a': 1}`, `123`, `True`), and `enum`/`allowedValues` lists are rendered as
 * a Python list repr. {@link pyRepr} reproduces that.
 *
 * Keyword coverage matches the keywords present in {@link MANDATE_JSON_SCHEMA}
 * and the constraint sub-schemas the mandate uses: required, additional
 * properties, pattern, enum, type, minLength, maxLength, minItems, maxItems,
 * minProperties, maxProperties, minimum, maximum, exclusiveMinimum,
 * exclusiveMaximum. Each fixture pins the exact string, so an unhandled keyword
 * surfaces immediately as a failing test rather than a silent mismatch.
 */
function pythonJsonschemaMessage(
  error: ErrorObject,
  root: Record<string, unknown>,
  schema: Record<string, unknown>,
): string {
  const params = error.params as Record<string, unknown>;
  const value = instanceAt(error, root);
  switch (error.keyword) {
    case 'required':
      return `${pyRepr(params.missingProperty)} is a required property`;
    case 'additionalProperties':
      // CPython jsonschema reports ALL extra keys in ONE message, sorted by str,
      // with verb agreement: `('b' was unexpected)` vs `('b', 'c' were
      // unexpected)`. ajv (allErrors: false) only surfaces ONE extra per error
      // (`params.additionalProperty`), so we recompute the full set from the
      // instance + the applicable subschema, exactly like Python's
      // `find_additional_properties` (instance keys not in `properties` and not
      // matched by `patternProperties`).
      return additionalPropertiesMessage(error, value, schema);
    case 'pattern':
      return `${pyRepr(value)} does not match ${pyRepr(params.pattern)}`;
    case 'enum':
      return `${pyRepr(value)} is not one of ${pyReprList(
        params.allowedValues as unknown[],
      )}`;
    case 'type':
      // CPython jsonschema renders a type UNION as the per-type reprs joined by
      // ", " (e.g. `is not of type 'number', 'boolean'`), NOT as a Python list
      // repr (`['number', 'boolean']`). A single type is just its repr. ajv hands
      // `params.type` back as an array for a union, a string for a single type.
      return `${pyRepr(value)} is not of type ${pyReprTypeList(params.type)}`;
    case 'minLength': {
      const limit = params.limit as number;
      return limit === 1
        ? `${pyRepr(value)} should be non-empty`
        : `${pyRepr(value)} is too short`;
    }
    case 'maxLength':
      return `${pyRepr(value)} is too long`;
    case 'minItems': {
      const limit = params.limit as number;
      return limit === 1
        ? `${pyRepr(value)} should be non-empty`
        : `${pyRepr(value)} is too short`;
    }
    case 'maxItems':
      return `${pyRepr(value)} is too long`;
    case 'minProperties': {
      const limit = params.limit as number;
      return limit === 1
        ? `${pyRepr(value)} should be non-empty`
        : `${pyRepr(value)} does not have enough properties`;
    }
    case 'maxProperties':
      return `${pyRepr(value)} has too many properties`;
    case 'minimum':
      return `${pyRepr(value)} is less than the minimum of ${pyRepr(
        params.limit,
      )}`;
    case 'maximum':
      return `${pyRepr(value)} is greater than the maximum of ${pyRepr(
        params.limit,
      )}`;
    case 'exclusiveMinimum':
      return `${pyRepr(value)} is less than or equal to the minimum of ${pyRepr(
        params.limit,
      )}`;
    case 'exclusiveMaximum':
      return `${pyRepr(
        value,
      )} is greater than or equal to the maximum of ${pyRepr(params.limit)}`;
    default:
      // Defensive: an unhandled keyword would mismatch a fixture and fail the
      // test loudly. Surface ajv's own message so the gap is diagnosable rather
      // than emitting a misleading Python-shaped string.
      return error.message ?? `validation failed: ${error.keyword}`;
  }
}

/**
 * Reproduce CPython jsonschema's `additionalProperties: false` message for ALL
 * extra keys at once (ajv only reports one per error). Mirrors jsonschema's
 * `_keywords.additionalProperties` exactly:
 *   - extras = instance keys not in the subschema's `properties` and not matched
 *     by its joined `patternProperties` regexes (`find_additional_properties`).
 *   - extras are `sorted(extras, key=str)`.
 *   - WITHOUT patternProperties: `Additional properties are not allowed (<joined>
 *     <was|were> unexpected)` (`was` for one extra, `were` for many).
 *   - WITH patternProperties: `<joined> <does|do> not match any of the regexes:
 *     <sorted pattern reprs>` (`does` for one, `do` for many).
 */
function additionalPropertiesMessage(
  error: ErrorObject,
  value: unknown,
  schema: Record<string, unknown>,
): string {
  const subschema = resolveSubschema(error.schemaPath, schema);
  const props =
    (subschema?.properties as Record<string, unknown> | undefined) ?? {};
  const patternProps =
    (subschema?.patternProperties as Record<string, unknown> | undefined) ?? {};
  const patternKeys = Object.keys(patternProps);

  // Recompute extras the way Python `find_additional_properties` does.
  let extras: string[];
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const joinedPattern =
      patternKeys.length > 0 ? new RegExp(patternKeys.join('|')) : null;
    extras = Object.keys(value as Record<string, unknown>).filter((key) => {
      if (key in props) return false;
      if (joinedPattern && joinedPattern.test(key)) return false;
      return true;
    });
  } else {
    // Fallback (subschema/instance not resolvable): use ajv's single key so we
    // still emit a coherent message rather than throwing.
    const params = error.params as { additionalProperty?: string };
    extras = params.additionalProperty !== undefined ? [params.additionalProperty] : [];
  }

  // Python: `sorted(extras, key=str)` -> lexicographic by string value.
  extras.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const joinedExtras = extras.map(pyRepr).join(', ');

  if (patternKeys.length > 0) {
    const verb = extras.length === 1 ? 'does' : 'do';
    const sortedPatterns = [...patternKeys].sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    const patterns = sortedPatterns.map(pyRepr).join(', ');
    return `${joinedExtras} ${verb} not match any of the regexes: ${patterns}`;
  }

  const verb = extras.length === 1 ? 'was' : 'were';
  return `Additional properties are not allowed (${joinedExtras} ${verb} unexpected)`;
}

/**
 * Resolve the subschema that OWNS the failing keyword from an ajv `schemaPath`
 * (a JSON Pointer like `#/properties/inner/additionalProperties`). Returns the
 * parent object schema (the path minus its final keyword segment), or `null` if
 * the path cannot be walked. Used to recover `properties`/`patternProperties`
 * for the additionalProperties message, which ajv's per-error params omit.
 *
 * The walk must handle ARRAY index tokens, not just object keys: when
 * constraints are COMPOSED (`composeEffectiveConstraints` emits `{allOf: [...]}`
 * once a delegation scope restriction is intersected), ajv reports the failing
 * keyword under an applicator array, e.g. `#/allOf/0/additionalProperties` or
 * `#/anyOf/1/properties/.../additionalProperties`. A numeric token following an
 * applicator keyword (`allOf`/`anyOf`/`oneOf`/`prefixItems`/`items`) indexes
 * into that array. Treating arrays as un-walkable (the old behavior) left the
 * subschema unresolved, so `additionalPropertiesMessage` recomputed extras
 * against an EMPTY `properties` set and mislabeled ALLOWED keys as unexpected
 * (diverging from Python's `find_additional_properties`, which always uses the
 * failing subschema's own `properties`/`patternProperties`).
 */
function resolveSubschema(
  schemaPath: string | undefined,
  schema: Record<string, unknown>,
): Record<string, unknown> | null {
  if (schemaPath === undefined) return null;
  // Strip the leading "#" and the trailing keyword (e.g. "/additionalProperties").
  const pointer = schemaPath.startsWith('#') ? schemaPath.slice(1) : schemaPath;
  const tokens = pointer
    .split('/')
    .slice(1)
    .map((t) => t.replace(/~1/g, '/').replace(/~0/g, '~'));
  if (tokens.length === 0) return schema;
  tokens.pop(); // drop the keyword segment; we want its parent schema object.
  let current: unknown = schema;
  for (const token of tokens) {
    if (Array.isArray(current)) {
      // An applicator array (`allOf`/`anyOf`/`oneOf`/`prefixItems`/`items`): the
      // token is a numeric index into it. Mirror `instanceAt`'s array walk so a
      // composed-schema path like `allOf/0` resolves to the branch subschema.
      current = current[Number(token)];
    } else if (current !== null && typeof current === 'object') {
      current = (current as Record<string, unknown>)[token];
    } else {
      return null;
    }
  }
  return current !== null && typeof current === 'object' && !Array.isArray(current)
    ? (current as Record<string, unknown>)
    : null;
}

// ---------------------------------------------------------------------------
// CPython repr() for JSON-shaped values (instance + schema literals)
// ---------------------------------------------------------------------------

/**
 * Render a JSON-shaped value the way CPython's `repr()` would, so jsonschema
 * message text matches byte-for-byte. Shares the rendering rules with the
 * mandate-models `pyRepr` (strings single/double-quoted per CPython, control
 * chars escaped, dict/list rendered recursively with `{k: v}` / `[a, b]`
 * spacing, `None`/`True`/`False`, `nan`/`inf`).
 */
function pyRepr(value: unknown): string {
  if (typeof value === 'string') return pyReprString(value);
  if (value === null || value === undefined) return 'None';
  if (value === true) return 'True';
  if (value === false) return 'False';
  if (typeof value === 'number') return pyReprNumber(value);
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) {
    return `[${value.map(pyRepr).join(', ')}]`;
  }
  if (typeof value === 'object') {
    const inner = Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${pyRepr(k)}: ${pyRepr(v)}`)
      .join(', ');
    return `{${inner}}`;
  }
  return String(value);
}

/** CPython list repr: `[repr(a), repr(b), ...]`. */
function pyReprList(values: unknown[]): string {
  return `[${values.map(pyRepr).join(', ')}]`;
}

/**
 * Render a jsonschema `type` keyword value the way CPython jsonschema's `type`
 * keyword does: `", ".join(repr(t) for t in ensure_list(types))`. A union array
 * becomes `'a', 'b'` (NOT a list repr `['a', 'b']`); a single type string is
 * just its repr `'a'`. Order follows the schema declaration (jsonschema does not
 * sort the type list).
 */
function pyReprTypeList(type: unknown): string {
  const types = Array.isArray(type) ? type : [type];
  return types.map(pyRepr).join(', ');
}

/**
 * CPython `repr()` of a `str`. Single-quote by default; double-quote when the
 * string contains a `'` and no `"`. Backslash-escapes the active quote and `\`;
 * `\t`/`\n`/`\r` use named escapes; other non-printable code points escape as
 * `\xNN`/`\uNNNN`/`\UNNNNNNNN`. Iterates by code point so astral chars produce
 * a single `\U........`.
 */
function pyReprString(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (ch === quote || ch === '\\') {
      out += '\\' + ch;
    } else if (ch === '\t') {
      out += '\\t';
    } else if (ch === '\n') {
      out += '\\n';
    } else if (ch === '\r') {
      out += '\\r';
    } else if (isPyPrintable(ch, cp)) {
      out += ch;
    } else if (cp < 0x100) {
      out += '\\x' + cp.toString(16).padStart(2, '0');
    } else if (cp < 0x10000) {
      out += '\\u' + cp.toString(16).padStart(4, '0');
    } else {
      out += '\\U' + cp.toString(16).padStart(8, '0');
    }
  }
  return out + quote;
}

const NON_PRINTABLE_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

/** True when CPython `str.isprintable()` would treat this code point as printable. */
function isPyPrintable(ch: string, cp: number): boolean {
  if (cp === 0x20) return true;
  return !NON_PRINTABLE_RE.test(ch);
}

/**
 * CPython `repr()` of a number for jsonschema messages. JSON-sourced numbers
 * carry no int/float tag, so an integer-valued finite number reprs without a
 * trailing `.0` (matching `json.loads("100.0")` -> `100`). Non-finite values
 * map to `nan`/`inf`/`-inf` (CPython), not JS `NaN`/`Infinity`.
 */
function pyReprNumber(n: number): string {
  if (Number.isNaN(n)) return 'nan';
  if (n === Infinity) return 'inf';
  if (n === -Infinity) return '-inf';
  return String(n);
}

// ---------------------------------------------------------------------------
// Constraint validation (constraints-as-schema)
// ---------------------------------------------------------------------------

const JSON_SCHEMA_KEYWORDS = new Set<string>([
  '$schema',
  '$id',
  '$ref',
  '$defs',
  'type',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'allOf',
  'anyOf',
  'oneOf',
  'not',
  'enum',
  'const',
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'minLength',
  'maxLength',
  'pattern',
  'minItems',
  'maxItems',
  'format',
]);

/**
 * Validate that `constraints` are well-formed, and (if `action` is supplied)
 * that the action satisfies the constraints treated as a JSON Schema. Mirrors
 * Python `validate_constraints`, returning `[compliant, errors]`.
 *
 * The constraint-schema validity check mirrors Python's
 * `Draft202012Validator.check_schema(constraints)` (a meta-schema validation).
 * On a meta-schema failure Python emits `"Constraint schema invalid:
 * <jsonschema-internal-message>"`; the JS engine emits the same PREFIX and a
 * best-effort tail. The fixtures assert the boolean + prefix for those cases
 * (the jsonschema-internal tail is not byte-pinned — see the test rationale).
 * The action-violation path emits `"Action violates constraint: <message>"`,
 * which IS byte-pinned because the constraint sub-schema uses the same stable
 * keyword templates {@link pythonJsonschemaMessage} reproduces.
 */
export function validateConstraints(
  constraints: Record<string, unknown>,
  action?: Record<string, unknown> | null,
): [boolean, string[]] {
  const errors: string[] = [];

  // Python `if not constraints:` -- falsy (empty dict / null) is non-compliant.
  if (!constraints || Object.keys(constraints).length === 0) {
    errors.push('Constraints must be non-empty');
    return [false, errors];
  }

  // Meta-schema validity (Python Draft202012Validator.check_schema).
  const schemaError = checkConstraintSchema(constraints);
  if (schemaError !== null) {
    errors.push(`Constraint schema invalid: ${schemaError}`);
    return [false, errors];
  }

  if (action !== undefined && action !== null) {
    const actionError = validateAgainstSchema(constraints, action);
    if (actionError !== null) {
      errors.push(`Action violates constraint: ${actionError}`);
      return [false, errors];
    }
  }

  return [true, errors];
}

/**
 * Compile `constraints` as a JSON Schema, returning a CPython-jsonschema-style
 * meta-schema error message, or `null` if the schema is well-formed. ajv's
 * `compile` throws on a structurally-invalid schema; the thrown message is
 * ajv-internal (not byte-equal to CPython's), so the prefix is what the
 * fixtures pin. A well-formed schema returns `null`.
 */
function checkConstraintSchema(
  constraints: Record<string, unknown>,
): string | null {
  try {
    compileConstraintSchema(constraints);
    return null;
  } catch (err) {
    return cpythonMetaSchemaMessage(constraints, (err as Error).message);
  }
}

/**
 * Best-effort CPython meta-schema message. CPython's `check_schema` reports the
 * failing meta-schema keyword (e.g. `"'not-a-type' is not valid under any of
 * the given schemas"` for a bad `type`, `"'x' is not of type 'number'"` for a
 * bad `minimum`). These are jsonschema-internal and version-coupled; rather
 * than reproduce the meta-schema validator, we cover the cases the fixtures
 * exercise (bad `type` enum, wrong-typed numeric keyword) and fall back to
 * ajv's message otherwise. Parity is asserted on the boolean + the
 * `"Constraint schema invalid: "` PREFIX; the tail is best-effort.
 */
function cpythonMetaSchemaMessage(
  constraints: Record<string, unknown>,
  ajvMessage: string,
): string {
  // Bad `type` value (not a known JSON Schema type) -> CPython: "<repr> is not
  // valid under any of the given schemas".
  const typeValue = constraints.type;
  const VALID_TYPES = new Set([
    'null',
    'boolean',
    'object',
    'array',
    'number',
    'string',
    'integer',
  ]);
  if (typeof typeValue === 'string' && !VALID_TYPES.has(typeValue)) {
    return `${pyRepr(typeValue)} is not valid under any of the given schemas`;
  }
  // Numeric keyword given a non-number -> CPython: "<repr> is not of type 'number'".
  for (const key of ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum'] as const) {
    if (key in constraints && typeof constraints[key] !== 'number') {
      return `${pyRepr(constraints[key])} is not of type 'number'`;
    }
  }
  return ajvMessage;
}

const constraintSchemaCache = new Map<string, ValidateFunction>();

/** Compile a constraints-as-schema validator, caching by canonical key. */
function compileConstraintSchema(
  constraints: Record<string, unknown>,
): ValidateFunction {
  const key = JSON.stringify(constraints);
  const cached = constraintSchemaCache.get(key);
  if (cached) {
    return cached;
  }
  const validate = ajv.compile(constraints);
  constraintSchemaCache.set(key, validate);
  return validate;
}

/**
 * Validate `action` against `schema`, returning a CPython-jsonschema message
 * for the first violation, or `null` if it passes.
 */
function validateAgainstSchema(
  schema: Record<string, unknown>,
  action: Record<string, unknown>,
): string | null {
  const validate = compileConstraintSchema(schema);
  const ok = validate(action);
  if (ok) {
    return null;
  }
  const errors = validate.errors ?? [];
  if (errors.length === 0) {
    return null;
  }
  return pythonJsonschemaMessage(selectError(errors), action, schema);
}

// ---------------------------------------------------------------------------
// Delegation scope composition
// ---------------------------------------------------------------------------

/**
 * Convert a delegation `scope_restriction` into a JSON Schema. Mirrors Python
 * `_scope_restriction_to_schema`, returning `[schema | null, errors]`.
 *
 * Supported forms: a JSON Schema object (detected by the presence of any JSON
 * Schema keyword) and the `{"max_spend": number}` shorthand (rejecting a bool,
 * which is not an `int|float` in Python). Anything else fails closed.
 */
export function scopeRestrictionToSchema(
  scopeRestriction: Record<string, unknown> | null | undefined,
): [Record<string, unknown> | null, string[]] {
  if (
    scopeRestriction === null ||
    scopeRestriction === undefined ||
    typeof scopeRestriction !== 'object' ||
    Array.isArray(scopeRestriction) ||
    Object.keys(scopeRestriction).length === 0
  ) {
    return [null, ['unsupported_scope_restriction']];
  }

  const hasSchemaKeyword = Object.keys(scopeRestriction).some((k) =>
    JSON_SCHEMA_KEYWORDS.has(k),
  );
  if (hasSchemaKeyword) {
    const schemaError = checkConstraintSchema(scopeRestriction);
    if (schemaError !== null) {
      return [null, [`unsupported_scope_restriction: ${schemaError}`]];
    }
    return [scopeRestriction, []];
  }

  const maxSpend = scopeRestriction.max_spend;
  const keys = Object.keys(scopeRestriction);
  // Python: `set(scope_restriction) == {"max_spend"}` AND isinstance(max_spend,
  // int|float) AND not isinstance(max_spend, bool). A JS `boolean` is rejected
  // to match `not isinstance(_, bool)`.
  if (
    keys.length === 1 &&
    keys[0] === 'max_spend' &&
    typeof maxSpend === 'number'
  ) {
    return [
      {
        type: 'object',
        properties: {
          max_spend: {
            type: 'number',
            maximum: maxSpend,
          },
        },
      },
      [],
    ];
  }

  return [
    null,
    ['unsupported_scope_restriction: expected JSON Schema or max_spend shorthand'],
  ];
}

/**
 * Intersect mandate constraints with every delegation scope restriction.
 * Mirrors Python `compose_effective_constraints`, returning `[effective |
 * null, errors]`. When no scope adds a schema, the original constraints are
 * returned unchanged; otherwise an `{allOf: [...]}` intersection.
 */
export function composeEffectiveConstraints(
  constraints: Record<string, unknown>,
  chain: DelegationLink[],
): [Record<string, unknown> | null, string[]] {
  const schemas: Record<string, unknown>[] = [constraints];
  const errors: string[] = [];

  chain.forEach((link, i) => {
    if (link.scopeRestriction === null || link.scopeRestriction === undefined) {
      return;
    }
    const [schema, scopeErrors] = scopeRestrictionToSchema(link.scopeRestriction);
    if (scopeErrors.length > 0) {
      for (const error of scopeErrors) {
        errors.push(`link ${i}: ${error}`);
      }
      return;
    }
    if (schema !== null) {
      schemas.push(schema);
    }
  });

  if (errors.length > 0) {
    return [null, errors];
  }
  if (schemas.length === 1) {
    return [constraints, []];
  }
  return [{ allOf: schemas }, []];
}

// ---------------------------------------------------------------------------
// Temporal validity
// ---------------------------------------------------------------------------

/**
 * Check whether a mandate's validity window is currently satisfied. Mirrors
 * Python `check_temporal_validity`, returning `[valid, errors]`.
 *
 * @param validity The mandate's validity window.
 * @param options.now Current time as epoch ms (defaults to `Date.now()`).
 *   Python uses `datetime.now(timezone.utc)`; the comparison is `now < nb` /
 *   `now > na`, reproduced here in epoch ms.
 * @param options.sequenceKey The sequence key to match (sequence mode).
 * @param options.stateActive Whether the named state condition is active.
 */
export function checkTemporalValidity(
  validity: ValidityWindow,
  options: {
    now?: number;
    sequenceKey?: string | null;
    stateActive?: boolean | null;
  } = {},
): [boolean, string[]] {
  const errors: string[] = [];
  const now = options.now ?? Date.now();
  const sequenceKey = options.sequenceKey ?? null;
  const stateActive = options.stateActive ?? null;

  if (validity.mode === TemporalMode.WINDOWED) {
    if (
      validity.notBefore === null ||
      validity.notBefore === undefined ||
      validity.notAfter === null ||
      validity.notAfter === undefined
    ) {
      errors.push('Windowed mode requires not_before and not_after');
      return [false, errors];
    }
    const nb = parseIsoMs(validity.notBefore);
    const na = parseIsoMs(validity.notAfter);
    if (nb === null || na === null) {
      // Python: `datetime.fromisoformat(...)` raises ValueError ->
      // f"Invalid timestamp format: {e}". The Python message embeds the
      // ValueError text; reproduce CPython's fromisoformat message.
      const bad = nb === null ? validity.notBefore : validity.notAfter;
      errors.push(
        `Invalid timestamp format: ${cpythonFromisoformatError(bad)}`,
      );
      return [false, errors];
    }
    if (now < nb) {
      errors.push(`Mandate not yet valid (not_before: ${validity.notBefore})`);
      return [false, errors];
    }
    if (now > na) {
      errors.push(`Mandate expired (not_after: ${validity.notAfter})`);
      return [false, errors];
    }
  } else if (validity.mode === TemporalMode.SEQUENCE) {
    if (validity.sequenceKey === null || validity.sequenceKey === undefined) {
      errors.push('Sequence mode requires sequence_key');
      return [false, errors];
    }
    if (sequenceKey !== null && sequenceKey !== validity.sequenceKey) {
      errors.push(
        `Sequence key mismatch: mandate=${validity.sequenceKey}, ` +
          `provided=${sequenceKey}`,
      );
      return [false, errors];
    }
  } else if (validity.mode === TemporalMode.STATE_BOUND) {
    if (
      validity.stateCondition === null ||
      validity.stateCondition === undefined
    ) {
      errors.push('State-bound mode requires state_condition');
      return [false, errors];
    }
    if (stateActive !== null && !stateActive) {
      errors.push(
        `State condition '${validity.stateCondition}' is not active`,
      );
      return [false, errors];
    }
  }

  return [true, errors];
}

/**
 * Parse an ISO-8601 timestamp to epoch ms, mirroring Python
 * `datetime.fromisoformat(value.replace("Z", "+00:00"))`. Returns `null` if the
 * string is not a valid CPython isoformat.
 *
 * KNOWN PARITY RESIDUAL (accepted 2026-05-29, fail-CLOSED / safe direction;
 * unreachable from real data -- same posture as the predicate ISO/parse-boundary
 * residuals in `predicate.ts`): for EXOTIC/INVALID UTC offsets the underlying
 * `Date.parse` diverges from CPython `fromisoformat`. CPython 3.12 ACCEPTS an
 * out-of-range offset minute like `+00:99` (it normalizes to `+01:39`), whereas
 * V8 `Date.parse` returns `NaN` for it, so this returns `null` and the temporal
 * check treats the timestamp as a bad timestamp and REJECTS the mandate. That is
 * TS being STRICTER than Python on an invalid offset, never looser -- no
 * fail-open. CPython's own behavior here is version-dependent (3.9 != 3.12), and
 * real Concordia timestamps are normal `...Z` / `+HH:MM`. Full CPython-
 * fromisoformat offset parity is deliberately NOT chased (a version-coupled
 * rabbit hole on inputs that do not occur).
 */
function parseIsoMs(value: string): number | null {
  const s = value.replace(/Z/g, '+00:00');
  if (cpythonFromisoformatError(value) !== null) {
    return null;
  }
  const hasOffset = /[+-]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?$/.test(s);
  const forParse = hasOffset ? s : s + 'Z';
  const ms = Date.parse(forParse);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Reproduce CPython's `datetime.fromisoformat` ValueError text for the value
 * the temporal check feeds it. Returns `null` when the string parses cleanly.
 * The Python error embeds the POST-`Z`-replace string in the message, matching
 * `value.replace("Z", "+00:00")` before `fromisoformat`.
 */
function cpythonFromisoformatError(value: string): string | null {
  const s = value.replace(/Z/g, '+00:00');
  const m =
    /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,6})?)?(?:[+-]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?)?)?$/.exec(
      s,
    );
  if (m === null) {
    return `Invalid isoformat string: '${s}'`;
  }
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = m[4] !== undefined ? Number(m[4]) : 0;
  const minute = m[5] !== undefined ? Number(m[5]) : 0;
  const second = m[6] !== undefined ? Number(m[6]) : 0;
  if (month < 1 || month > 12) return 'month must be in 1..12';
  const isLeap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const daysInMonth =
    [31, isLeap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1] ??
    31;
  if (day < 1 || day > daysInMonth) return 'day is out of range for month';
  if (hour > 23) return 'hour must be in 0..23';
  if (minute > 59) return 'minute must be in 0..59';
  if (second > 59) return 'second must be in 0..59';
  return null;
}

// ---------------------------------------------------------------------------
// Delegation chain verification
// ---------------------------------------------------------------------------

/**
 * Verify the integrity of a delegation chain. Mirrors Python
 * `verify_delegation_chain`, returning `[valid, errors]`. Checks: chain starts
 * from `issuer` and ends at `subject`, each link's `delegator` matches the
 * previous link's `delegate`, and each link's signature is valid against the
 * delegator's public key.
 *
 * @param publicKeys Map of agent_id -> raw 32-byte Ed25519 public key (or a
 *   {@link KeyPair}). Python passes public-key OBJECTS; the TS `verify()`
 *   accepts raw bytes / a KeyPair. ES256 delegator keys are deferred: a link
 *   with a non-EdDSA `algorithm` fails the signature check fail-closed BEFORE
 *   any Ed25519 verification runs, matching Python `verify_signature(...,
 *   alg=link.algorithm)` which rejects an `algorithm`/key-curve mismatch (or any
 *   unknown `alg`). This closes the fail-open where an `algorithm:"ES256"` link
 *   carrying a genuine Ed25519 signature would otherwise pass the EdDSA verifier.
 */
export function verifyDelegationChain(
  chain: DelegationLink[],
  issuer: string,
  subject: string,
  publicKeys: Record<string, Uint8Array | KeyPair>,
): [boolean, string[]] {
  const errors: string[] = [];

  if (chain.length === 0) {
    return [true, errors]; // No chain = direct mandate, always valid.
  }

  const head = chain[0] as DelegationLink;
  const tail = chain[chain.length - 1] as DelegationLink;

  if (head.delegator !== issuer) {
    errors.push(
      `Chain root mismatch: expected issuer=${issuer}, ` +
        `got delegator=${head.delegator}`,
    );
  }

  if (tail.delegate !== subject) {
    errors.push(
      `Chain tail mismatch: expected subject=${subject}, ` +
        `got delegate=${tail.delegate}`,
    );
  }

  chain.forEach((link, i) => {
    const prev = chain[i - 1];
    if (i > 0 && prev !== undefined && link.delegator !== prev.delegate) {
      errors.push(
        `Chain break at link ${i}: delegator=${link.delegator} ` +
          `!= previous delegate=${prev.delegate}`,
      );
    }

    const pubKey = publicKeys[link.delegator];
    if (pubKey === undefined) {
      errors.push(
        `No public key for delegator '${link.delegator}' at link ${i}`,
      );
      return;
    }

    const linkDict = delegationLinkToDict(link);
    const sig = (linkDict.signature as string) ?? '';
    delete linkDict.signature;
    if (!sig) {
      errors.push(`Missing signature at link ${i}`);
      return;
    }

    // Algorithm gate (FAIL-CLOSED, parity with Python). Python recomputes the
    // signing payload from the link's `to_dict()` (which embeds `algorithm`) and
    // calls `verify_signature(..., alg=link.algorithm)`. That helper returns
    // False for ANY `alg` other than a matched key/curve pair: `ES256` against an
    // Ed25519 key is rejected (`isinstance(... EllipticCurvePublicKey)` fails),
    // and any unknown `alg` (e.g. `RS256`) hits the `else: return False` branch.
    // The merged TS `verify()` is Ed25519-only and IGNORES `link.algorithm`, so
    // an attacker-marked `algorithm:"ES256"` link carrying a genuine Ed25519
    // signature would pass `verify()` (true) here -> valid=true, a FAIL-OPEN that
    // Python rejects. We gate first: treat any non-EdDSA algorithm as an invalid
    // signature WITHOUT running the Ed25519 check, reproducing Python's reject
    // and the identical `Invalid signature at delegation link {i}` error string.
    const linkAlgorithm = linkDict.algorithm;
    if (linkAlgorithm !== 'EdDSA') {
      errors.push(`Invalid signature at delegation link ${i}`);
      return;
    }

    if (!verify(linkDict, sig, pubKey)) {
      errors.push(`Invalid signature at delegation link ${i}`);
    }
  });

  return [errors.length === 0, errors];
}

// ---------------------------------------------------------------------------
// Revocation (network fetch DEFERRED; injectable hook)
// ---------------------------------------------------------------------------

/**
 * A revocation checker resolves whether a mandate id is still valid against a
 * revocation endpoint, returning `[notRevoked, errors]` exactly as Python
 * `check_revocation`. The network fetch itself is DEFERRED in this PR; a caller
 * may inject this hook to supply revocation records (or a future PR ports the
 * default `urllib`-style fetch). Fail-closed semantics (an unreachable endpoint
 * -> `[false, [...]]`) are the hook's responsibility, matching Python.
 */
export type RevocationChecker = (
  mandateId: string,
  endpoint: string,
) => [boolean, string[]];

// ---------------------------------------------------------------------------
// Full mandate verification
// ---------------------------------------------------------------------------

/** Options for {@link verifyMandate}, mirroring Python `verify_mandate`'s kwargs. */
export interface VerifyMandateOptions {
  /** Override "now" as epoch ms for the temporal check. */
  now?: number;
  /** Sequence key for sequence-mode validity. */
  sequenceKey?: string | null;
  /** Whether the state condition is active (state_bound mode). */
  stateActive?: boolean | null;
  /** Optional action dict to validate against the (effective) constraints. */
  action?: Record<string, unknown> | null;
  /** Map of agent_id -> raw public key (or KeyPair) for chain verification. */
  delegationPublicKeys?: Record<string, Uint8Array | KeyPair> | null;
  /** Whether to check revocation status. Default `true` (matches Python). */
  checkRevocationStatus?: boolean;
  /**
   * Injectable revocation checker. The network fetch is deferred; with no
   * checker injected and a fetch required, {@link verifyMandate} throws.
   */
  revocationChecker?: RevocationChecker;
  /**
   * When true (default), sequence and state-bound mandates require
   * caller-provided binding context before authority is granted.
   */
  requireBindingContext?: boolean;
}

/**
 * Verify a mandate credential against all five checks. Mirrors Python
 * `verify_mandate`, returning a {@link MandateVerificationResult} with the same
 * `checks` keys, `errors`, `warnings`, and `failureReason` ordering.
 *
 * Revocation network I/O is DEFERRED (see the module docblock). With the
 * default `checkRevocationStatus: false` (or no endpoint) the
 * `revocation_status` check is true and matches Python's "endpoint not checked"
 * outcome. With `checkRevocationStatus: true` + an endpoint + no
 * `revocationChecker`, this throws {@link MandateValidationError} rather than
 * fail-open.
 *
 * @param mandate A {@link Mandate} or its wire dict.
 * @param issuerPublicKey Raw 32-byte Ed25519 public key (or {@link KeyPair}).
 */
export function verifyMandate(
  mandate: Mandate | Record<string, unknown>,
  issuerPublicKey: Uint8Array | KeyPair,
  options: VerifyMandateOptions = {},
): MandateVerificationResult {
  const checkRevocationStatus = options.checkRevocationStatus ?? true;
  const requireBindingContext = options.requireBindingContext ?? true;

  // Convert dict to Mandate if needed (Python: isinstance(mandate, dict)).
  let mandateObj: Mandate;
  let mandateDict: Record<string, unknown>;
  if (isMandate(mandate)) {
    mandateObj = mandate;
    mandateDict = mandateToDict(mandate);
  } else {
    mandateObj = mandateFromDict(mandate);
    mandateDict = mandate;
  }

  const result = makeMandateVerificationResult({
    valid: false,
    mandateId: mandateObj.mandateId,
    issuer: mandateObj.issuer,
    subject: mandateObj.subject,
  });

  // --- Check 0: Schema validation ---
  const schemaErrors = validateMandateSchema(mandateDict);
  if (schemaErrors.length > 0) {
    result.checks.schema = false;
    result.errors.push(...schemaErrors);
    return result;
  }
  result.checks.schema = true;

  // --- Check 1: Issuer signature ---
  const sig = (mandateDict.signature as string) ?? '';
  if (!sig) {
    result.checks.issuer_signature = false;
    result.errors.push('Missing mandate signature');
    return result;
  }
  const signable: Record<string, unknown> = { ...mandateDict };
  delete signable.signature;
  // EdDSA-only verify (the crypto layer's scope). An ES256 mandate would fail
  // here, matching the deferred-ES256 posture (fail-closed).
  const sigValid =
    mandateObj.algorithm === 'EdDSA' &&
    verify(signable, sig, issuerPublicKey);
  result.checks.issuer_signature = sigValid;
  if (!sigValid) {
    result.errors.push('Invalid issuer signature');
    return result;
  }

  // --- Check 1b: Signed lifecycle status ---
  result.checks.lifecycle_status = mandateObj.status === MandateStatus.ACTIVE;
  if (mandateObj.status !== MandateStatus.ACTIVE) {
    result.failureReason = `mandate_${mandateObj.status}`;
    result.errors.push(
      `Mandate lifecycle status is ${pyRepr(mandateObj.status)}`,
    );
    return result;
  }

  // --- Check 2: Temporal validity ---
  if (mandateObj.validity !== null && mandateObj.validity !== undefined) {
    if (
      requireBindingContext &&
      mandateObj.validity.mode === TemporalMode.SEQUENCE &&
      (options.sequenceKey === null || options.sequenceKey === undefined)
    ) {
      result.checks.temporal_validity = false;
      result.failureReason = 'missing_sequence_context';
      result.errors.push('Sequence mandate requires sequence_key context');
      return result;
    }
    if (
      requireBindingContext &&
      mandateObj.validity.mode === TemporalMode.STATE_BOUND &&
      (options.stateActive === null || options.stateActive === undefined)
    ) {
      result.checks.temporal_validity = false;
      result.failureReason = 'missing_state_context';
      result.errors.push('State-bound mandate requires state_active context');
      return result;
    }
    const [temporalValid, temporalErrors] = checkTemporalValidity(
      mandateObj.validity,
      {
        now: options.now,
        sequenceKey: options.sequenceKey,
        stateActive: options.stateActive,
      },
    );
    result.checks.temporal_validity = temporalValid;
    if (!temporalValid) {
      result.errors.push(...temporalErrors);
      return result;
    }
  } else {
    result.checks.temporal_validity = true;
    result.warnings.push(
      'No validity window specified — mandate has no temporal bounds',
    );
  }

  // --- Check 3: Constraint compliance ---
  const [constraintValid, constraintErrors] = validateConstraints(
    mandateObj.constraints,
  );
  result.checks.constraint_compliance = constraintValid;
  if (!constraintValid) {
    result.errors.push(...constraintErrors);
    return result;
  }

  // --- Check 4: Delegation chain ---
  let effectiveConstraints: Record<string, unknown> | null;
  if (mandateObj.delegationChain.length > 0) {
    const chainKeys = options.delegationPublicKeys ?? {};
    const [chainValid, chainErrors] = verifyDelegationChain(
      mandateObj.delegationChain,
      mandateObj.issuer,
      mandateObj.subject,
      chainKeys,
    );
    result.checks.delegation_chain = chainValid;
    if (!chainValid) {
      result.errors.push(...chainErrors);
      return result;
    }
    const [eff, scopeErrors] = composeEffectiveConstraints(
      mandateObj.constraints,
      mandateObj.delegationChain,
    );
    result.checks.delegation_scope = eff !== null;
    if (eff === null) {
      result.failureReason = 'unsupported_scope_restriction';
      result.errors.push(...scopeErrors);
      return result;
    }
    effectiveConstraints = eff;
  } else {
    result.checks.delegation_chain = true;
    effectiveConstraints = mandateObj.constraints;
  }

  // --- Check 4b: Effective action scope ---
  const [effValid, effErrors] = validateConstraints(
    effectiveConstraints,
    options.action,
  );
  result.checks.constraint_compliance = effValid;
  if (!effValid) {
    result.errors.push(...effErrors);
    return result;
  }

  // --- Check 5: Revocation status (network fetch DEFERRED) ---
  if (mandateObj.revocationEndpoint && checkRevocationStatus) {
    if (options.revocationChecker === undefined) {
      // DEFERRED network path: no fail-open. A future PR ports the urllib fetch
      // into a default checker. Pinned by the deferred_revocation_case fixture
      // + a skipped test.
      throw new MandateValidationError(
        'revocation check requires an injected revocationChecker; network fetch is deferred',
      );
    }
    const [notRevoked, revocationErrors] = options.revocationChecker(
      mandateObj.mandateId,
      mandateObj.revocationEndpoint,
    );
    result.checks.revocation_status = notRevoked;
    if (!notRevoked) {
      result.errors.push(...revocationErrors);
      return result;
    }
  } else {
    result.checks.revocation_status = true;
    if (
      mandateObj.revocationEndpoint === null ||
      mandateObj.revocationEndpoint === undefined
    ) {
      result.warnings.push('No revocation endpoint — status not verified');
    }
  }

  // All checks passed.
  result.valid = true;
  return result;
}

/**
 * Discriminate a parsed {@link Mandate} from its wire dict. A Mandate has the
 * camelCase TS-facing fields (`mandateId`, `delegationChain`); a wire dict uses
 * snake_case (`mandate_id`). Checking for the camelCase marker is sufficient
 * and avoids treating a dict as a Mandate.
 */
function isMandate(value: Mandate | Record<string, unknown>): value is Mandate {
  return (
    typeof value === 'object' &&
    value !== null &&
    'mandateId' in value &&
    'delegationChain' in value
  );
}
