/**
 * Predicate type-profile registry for v0.6 deterministic semantics.
 *
 * Port of `concordia/predicate_type_profiles/` (the package `__init__.py`
 * registry plus the four built-in profile modules: authority_gate,
 * procurement_eligibility, policy_gate, non_deterministic_test).
 *
 * Cross-language parity is load-bearing in two ways:
 *   1. The deterministic-semantics gate decides whether `condition.result` is
 *      permitted, which gates whether a predicate can be signed at all (see
 *      `validate_predicate_for_write` / `verify_predicate`). A divergence would
 *      accept a predicate Python rejects (or vice versa).
 *   2. When the gate runs the deterministic-profile JSON-schema check, the
 *      ERROR STRINGS must match Python's `jsonschema` (Draft 2020-12) output
 *      verbatim, because `verify_predicate` surfaces them in its `errors[]`.
 *      Rather than re-implement a general JSON-schema engine, this module
 *      validates the FOUR fixed built-in schemas with focused checks whose
 *      messages reproduce `jsonschema`'s exactly for those schema shapes. The
 *      parity is asserted against fixtures generated FROM Python
 *      (`tests/fixtures/predicate/predicate_vectors.json`, `profile_cases`).
 *
 * Note on registration semantics: Python loads built-ins lazily into a
 * module-global `_REGISTRY` and lets callers register custom profiles. The TS
 * port keeps the same shape: built-ins are pre-registered, and
 * `registerPredicateTypeProfile` lets callers add or replace profiles. The
 * lazy-vs-eager distinction is not observable through `validateConditionForProfile`.
 */

/**
 * A predicate type profile: a type id, whether its condition is deterministic
 * (i.e. may carry a `result`), and the JSON-schema its condition must satisfy
 * when deterministic and a `result` is present.
 *
 * `conditionSchema` mirrors the Python profile module's `CONDITION_SCHEMA`
 * dict. Property order is preserved (it drives jsonschema-equivalent error
 * ordering), so it is modeled as an ordered list of property checks plus the
 * declared `required` set.
 */
export interface PredicateTypeProfile {
  typeId: string;
  isDeterministic: boolean;
  conditionSchema: ConditionSchema;
}

/**
 * A minimal model of the JSON-schemas the built-in profiles declare. These
 * schemas only ever use: `type: "object"`, an ordered `properties` map where
 * each property declares either an `enum` or a primitive `type`, a `required`
 * list, and `additionalProperties: true`. This covers every built-in profile;
 * it is intentionally NOT a general JSON-schema engine.
 */
interface ConditionSchema {
  /** Ordered property checks; order drives error-emission order (jsonschema). */
  properties: PropertyCheck[];
  /** Required property names (Python `required`). */
  required: string[];
}

type PropertyCheck =
  | { name: string; kind: 'enum'; values: (string | number | boolean | null)[] }
  | { name: string; kind: 'type'; jsonType: 'string' | 'object' | 'array' };

// ---------------------------------------------------------------------------
// Built-in profile schemas (mirror the four Python profile modules verbatim).
// ---------------------------------------------------------------------------

// authority_gate / approval_gate / jcs_edge all share this schema.
const AUTHORITY_GATE_SCHEMA: ConditionSchema = {
  properties: [
    { name: 'result', kind: 'enum', values: ['satisfied', 'denied'] },
  ],
  required: ['result'],
};

const PROCUREMENT_SCHEMA: ConditionSchema = {
  properties: [
    { name: 'result', kind: 'enum', values: ['satisfied', 'denied'] },
    { name: 'operation', kind: 'type', jsonType: 'string' },
    { name: 'limit', kind: 'type', jsonType: 'object' },
  ],
  required: ['result'],
};

const POLICY_GATE_SCHEMA: ConditionSchema = {
  properties: [
    { name: 'result', kind: 'enum', values: ['satisfied', 'denied'] },
    { name: 'all', kind: 'type', jsonType: 'array' },
    { name: 'any', kind: 'type', jsonType: 'array' },
  ],
  required: ['result'],
};

const NON_DETERMINISTIC_SCHEMA: ConditionSchema = {
  properties: [],
  required: [],
};

/**
 * The built-in profile registry, mirroring Python's `_BUILTIN_MODULES` map.
 * The three authority-family type ids all resolve to the authority-gate
 * schema, exactly as Python aliases them to the same module.
 */
const BUILTIN_PROFILES: Record<string, PredicateTypeProfile> = {
  'urn:concordia:predicate-type:authority_gate:v1': {
    typeId: 'urn:concordia:predicate-type:authority_gate:v1',
    isDeterministic: true,
    conditionSchema: AUTHORITY_GATE_SCHEMA,
  },
  'urn:concordia:predicate-type:approval_gate:v1': {
    typeId: 'urn:concordia:predicate-type:approval_gate:v1',
    isDeterministic: true,
    conditionSchema: AUTHORITY_GATE_SCHEMA,
  },
  'urn:concordia:predicate-type:jcs_edge:v1': {
    typeId: 'urn:concordia:predicate-type:jcs_edge:v1',
    isDeterministic: true,
    conditionSchema: AUTHORITY_GATE_SCHEMA,
  },
  'urn:concordia:predicate-type:procurement_eligibility:v1': {
    typeId: 'urn:concordia:predicate-type:procurement_eligibility:v1',
    isDeterministic: true,
    conditionSchema: PROCUREMENT_SCHEMA,
  },
  'urn:concordia:predicate-type:policy_gate:v1': {
    typeId: 'urn:concordia:predicate-type:policy_gate:v1',
    isDeterministic: true,
    conditionSchema: POLICY_GATE_SCHEMA,
  },
  'urn:concordia:predicate-type:non_deterministic_test:v1': {
    typeId: 'urn:concordia:predicate-type:non_deterministic_test:v1',
    isDeterministic: false,
    conditionSchema: NON_DETERMINISTIC_SCHEMA,
  },
};

const REGISTRY: Map<string, PredicateTypeProfile> = new Map(
  Object.entries(BUILTIN_PROFILES).map(([id, p]) => [id, p]),
);

/**
 * Register or replace a predicate type profile.
 * Mirrors Python `register_predicate_type_profile`.
 */
export function registerPredicateTypeProfile(
  typeId: string,
  options: { isDeterministic: boolean; conditionSchema: ConditionSchema },
): PredicateTypeProfile {
  const profile: PredicateTypeProfile = {
    typeId,
    isDeterministic: options.isDeterministic,
    conditionSchema: options.conditionSchema,
  };
  REGISTRY.set(typeId, profile);
  return profile;
}

/**
 * Return a registered profile (built-in or custom), or `null` if unknown.
 * Mirrors Python `get_predicate_type_profile`. Python loads built-ins lazily;
 * here they are pre-registered, which is behaviorally identical for callers.
 */
export function getPredicateTypeProfile(
  typeId: string,
): PredicateTypeProfile | null {
  return REGISTRY.get(typeId) ?? null;
}

/**
 * Format a JSON value the way Python's `repr()` does, so the JSON-schema error
 * strings this module emits are byte-identical to `jsonschema`'s (which builds
 * its messages from `repr(value)` / `repr(enum_list)`).
 *
 * Coverage (the only shapes that reach a profile condition value): `null`
 * (`None`), booleans (`True`/`False`), integers, floats, strings (single-quoted,
 * with Python's escaping for embedded quotes/backslashes), arrays, and objects.
 */
function pyRepr(value: unknown): string {
  if (value === null || value === undefined) return 'None';
  if (typeof value === 'boolean') return value ? 'True' : 'False';
  if (typeof value === 'number') {
    if (Number.isInteger(value)) return String(value);
    return String(value);
  }
  if (typeof value === 'string') return pyReprString(value);
  if (Array.isArray(value)) {
    return '[' + value.map(pyRepr).join(', ') + ']';
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).map(
      ([k, v]) => `${pyReprString(k)}: ${pyRepr(v)}`,
    );
    return '{' + entries.join(', ') + '}';
  }
  return String(value);
}

/**
 * Render a string the way Python's `repr()` renders a `str`: prefer single
 * quotes; switch to double quotes only when the string contains a single quote
 * but no double quote; otherwise single-quote and backslash-escape embedded
 * single quotes. Backslashes are escaped. This matches CPython's `str.__repr__`
 * for the ASCII-clean values that reach predicate conditions.
 */
function pyReprString(s: string): string {
  const hasSingle = s.includes("'");
  const hasDouble = s.includes('"');
  const quote = hasSingle && !hasDouble ? '"' : "'";
  let out = '';
  for (const ch of s) {
    if (ch === '\\') out += '\\\\';
    else if (ch === quote) out += '\\' + ch;
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else out += ch;
  }
  return quote + out + quote;
}

/**
 * The JSON `type` keyword's notion of an "object" (a plain mapping), tightened
 * to match Python's `isinstance(value, dict)`.
 *
 * Python's `validate_condition_for_profile` and `_schema_errors` gate the
 * condition on `isinstance(condition, dict)`, which is true ONLY for an actual
 * mapping. A class instance, a `Date`, a `Map`, a boxed primitive, etc. are NOT
 * dicts and Python rejects them. A naive `typeof === 'object'` check would
 * fail-open here: it accepts class instances and `Date`s that Python rejects.
 *
 * A "plain object" is one whose prototype is `Object.prototype` (a `{...}`
 * literal or `JSON.parse` output) or `null` (`Object.create(null)`). Anything
 * with a different prototype (class instances, `Date`, `Map`, `RegExp`, arrays,
 * etc.) is rejected, mirroring `isinstance(x, dict)` for the JSON-representable
 * inputs that reach a predicate condition.
 */
function isJsonObject(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Run the focused JSON-schema check for a deterministic profile, producing
 * error strings byte-identical to Python `jsonschema` (Draft 2020-12) for the
 * built-in profile schemas. Errors are emitted in schema-property declaration
 * order (jsonschema iterates the `properties` map in declaration order), with
 * the `enum` check on `result` taking the property's slot.
 */
function schemaErrors(
  schema: ConditionSchema,
  condition: Record<string, unknown>,
): string[] {
  const errors: string[] = [];
  // jsonschema emits property-level errors in `properties` declaration order.
  for (const prop of schema.properties) {
    if (!(prop.name in condition)) continue;
    const value = condition[prop.name];
    if (prop.kind === 'enum') {
      if (!prop.values.some((v) => v === value)) {
        const enumRepr =
          '[' + prop.values.map(pyRepr).join(', ') + ']';
        errors.push(`${pyRepr(value)} is not one of ${enumRepr}`);
      }
    } else {
      const ok =
        prop.jsonType === 'string'
          ? typeof value === 'string'
          : prop.jsonType === 'array'
            ? Array.isArray(value)
            : isJsonObject(value);
      if (!ok) {
        errors.push(`${pyRepr(value)} is not of type '${prop.jsonType}'`);
      }
    }
  }
  return errors;
}

/**
 * Validate a predicate condition against its type profile's deterministic
 * semantics. Mirrors Python `validate_condition_for_profile` exactly:
 *
 *   1. Unknown type id -> a single "must be registered before signing" error.
 *   2. Non-object condition -> "condition must be an object".
 *   3. Non-deterministic profile carrying `condition.result` -> the
 *      deterministic-semantics gate violation error.
 *   4. Deterministic profile carrying `condition.result` -> the profile
 *      JSON-schema is run and its (possibly empty) error list returned.
 *   5. Otherwise -> no errors.
 *
 * Returns the list of error message strings (empty when the condition is valid).
 */
export function validateConditionForProfile(
  typeId: string,
  condition: unknown,
): string[] {
  const profile = getPredicateTypeProfile(typeId);
  if (profile === null) {
    return [`predicate type profile must be registered before signing: ${typeId}`];
  }
  if (!isJsonObject(condition)) {
    return ['condition must be an object'];
  }
  const cond = condition as Record<string, unknown>;
  const hasResult = 'result' in cond;
  if (!profile.isDeterministic && hasResult) {
    return [
      'deterministic-semantics gate violation: condition.result is only ' +
        'allowed for deterministic predicate type profiles',
    ];
  }
  if (profile.isDeterministic && hasResult) {
    return schemaErrors(profile.conditionSchema, cond);
  }
  return [];
}
