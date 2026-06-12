/**
 * A CPython-`jsonschema`-faithful Draft 2020-12 validator, scoped to the keyword
 * subset the Concordia bundled schemas use.
 *
 * WHY A HAND-PORT RATHER THAN ajv (the mandate engine's approach):
 *   `concordia/schema_validator.py` returns the FULL ordered error list from
 *   `Draft202012Validator.iter_errors`, formatted as `"{json_path}: {message}"`.
 *   That surface needs three things ajv cannot reproduce byte-for-byte:
 *     1. CPython jsonschema's `iter_errors` ORDERING. Errors are yielded per node
 *        in the schema dict's KEY-INSERTION ORDER (verified: reordering `minimum`
 *        before/after `type` in a schema reorders the emitted errors), descending
 *        into `properties`/`items` at the point those keywords appear. ajv
 *        (`allErrors`) groups and orders errors by its own internal compilation,
 *        which does not match.
 *     2. The `json_path` shape (`$`, `$.scope.decision`, `$.references[1]`).
 *     3. CPython jsonschema's `validator` / `validator_value` stamping (the
 *        post-#95 no-echo error format renders the violated CONSTRAINT, so
 *        each error must carry its keyword and schema-side value), plus the
 *        exact `required` message template, value rendered with CPython
 *        `repr()` (shared via {@link pyRepr}).
 *   The mandate engine only needed the single best-match error + `"Schema: "`
 *   prefix, so ajv-translate sufficed there. Here the ordered list is the
 *   load-bearing contract, so this module re-implements the traversal directly.
 *   It reuses the SAME `pyRepr` rendering as the engine (now shared from
 *   `src/internal/py-repr.ts`), so the embedded-value text matches both layers.
 *
 * Supported applicators now include the §9.6 attestation schema's narrow
 * `$ref` / `$defs` / `oneOf` needs. Still unsupported: `anyOf`, `not`,
 * `propertyNames`, `dependentRequired`, `dependentSchemas`, `prefixItems`,
 * `uniqueItems`, `multipleOf`. If a schema carrying one of these reaches
 * {@link iterErrors}, the unknown keyword is IGNORED (jsonschema ignores unknown
 * keywords too), which would silently under-validate — so the consuming modules
 * MUST only feed schemas built from the supported subset. A
 * `validateSchemaKeywords` guard asserts this at module load for the bundled
 * schemas.
 */

import { pyRepr } from './py-repr.js';

/** A single validation error, mirroring a CPython jsonschema `ValidationError`. */
export interface SchemaError {
  /** The `error.json_path` ("$", "$.a", "$.a[0].b"). */
  jsonPath: string;
  /**
   * The `error.message` (CPython template, value rendered via `pyRepr`).
   *
   * SECURITY (post-#95 error-echo hardening): for every keyword EXCEPT
   * `required`, this template embeds the rejected INSTANCE value, so consumers
   * MUST NOT surface it. The public formatting layer
   * (`validation/schema-validator.ts`) renders `keyword` + `validatorValue`
   * instead, exactly like Python's `_format_validation_error`. The field is
   * kept because (a) Python's `ValidationError.message` keeps it too, and
   * (b) `required` messages (schema-side property names only) still use it.
   */
  message: string;
  /**
   * The CPython `error.validator`: the schema keyword that failed. `null`
   * mirrors CPython's `validator=None` (a boolean `false` schema), which the
   * formatter renders as the generic `'schema'` keyword.
   */
  keyword?: string | null;
  /** The CPython `error.validator_value`: the schema-side value of `keyword`. */
  validatorValue?: unknown;
  /** The CPython `error.schema`: the (sub)schema whose keyword failed. */
  schema?: unknown;
}

/**
 * A `format` checker: given a format name and a string instance, returns `true`
 * if it conforms. Mirrors the registered checks on Python's
 * `jsonschema.FormatChecker`. Non-string instances are NOT passed here (the
 * caller skips them, matching the custom Concordia checkers which return `True`
 * for non-strings so the `type` keyword catches them).
 */
export type FormatChecker = (format: string, value: string) => boolean;

interface ValidationContext {
  rootSchema: unknown;
  formatChecker?: FormatChecker;
  refStack: Set<string>;
}

/**
 * Yield validation errors for `instance` against `schema`, reproducing CPython
 * `Draft202012Validator(schema, format_checker=...).iter_errors(instance)` in
 * order. The returned list is ready to be formatted as `"{json_path}: {message}"`
 * by the caller.
 *
 * @param schema A JSON Schema object built from the supported keyword subset.
 * @param instance The instance to validate.
 * @param formatChecker Optional `format` assertion. When omitted, `format` is a
 *   no-op annotation (matching CPython jsonschema with NO `format_checker`, which
 *   never asserts formats).
 */
export function iterErrors(
  schema: unknown,
  instance: unknown,
  formatChecker?: FormatChecker,
): SchemaError[] {
  const errors: SchemaError[] = [];
  validateNode(schema, instance, '$', errors, {
    rootSchema: schema,
    formatChecker,
    refStack: new Set(),
  });
  return errors;
}

/**
 * Validate one instance against one (sub)schema at `path`, pushing errors in
 * CPython jsonschema's order: iterate the schema's keywords in DICT-INSERTION
 * order, applying each. A boolean schema (`true`/`false`) short-circuits (Draft
 * 2020-12: `false` rejects everything, `true` accepts).
 */
function validateNode(
  schema: unknown,
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  // Boolean schemas (Draft 2020-12). `false` rejects any instance; `true`
  // accepts. CPython's `false` message is the generic one below; CPython sets
  // `validator=None` / `validator_value=None` on it, mirrored here as
  // `keyword: null` / `validatorValue: null` (stamped eagerly so the keyword
  // loop of an ANCESTOR schema never claims this error as its own).
  if (schema === true) return;
  if (schema === false) {
    errors.push({
      jsonPath: path,
      message: `${pyRepr(instance)} is not allowed`,
      keyword: null,
      validatorValue: null,
      schema: false,
    });
    return;
  }
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) {
    return; // not a schema object; nothing to validate
  }
  const s = schema as Record<string, unknown>;

  // Iterate keywords in the schema's own insertion order (CPython jsonschema
  // applies its keyword validators in the order the keys appear in the schema
  // dict, which is the parse/insertion order — JS preserves this for string
  // keys, and `JSON.parse` preserves source order).
  for (const keyword of Object.keys(s)) {
    const value = s[keyword];
    const errorCountBefore = errors.length;
    switch (keyword) {
      case 'type':
        checkType(value, instance, path, errors);
        break;
      case 'enum':
        checkEnum(value as unknown[], instance, path, errors);
        break;
      case 'const':
        checkConst(value, instance, path, errors);
        break;
      case 'required':
        checkRequired(value as string[], instance, path, errors);
        break;
      case 'properties':
        checkProperties(value as Record<string, unknown>, instance, path, errors, ctx);
        break;
      case 'additionalProperties':
        checkAdditionalProperties(s, value, instance, path, errors, ctx);
        break;
      case 'patternProperties':
        checkPatternProperties(value as Record<string, unknown>, instance, path, errors, ctx);
        break;
      case 'items':
        checkItems(value, instance, path, errors, ctx);
        break;
      case 'contains':
        checkContains(value, instance, path, errors, ctx);
        break;
      case 'minItems':
        checkMinItems(value as number, instance, path, errors);
        break;
      case 'maxItems':
        checkMaxItems(value as number, instance, path, errors);
        break;
      case 'minLength':
        checkMinLength(value as number, instance, path, errors);
        break;
      case 'maxLength':
        checkMaxLength(value as number, instance, path, errors);
        break;
      case 'pattern':
        checkPattern(value as string, instance, path, errors);
        break;
      case 'minimum':
        checkMinimum(value as number, instance, path, errors);
        break;
      case 'maximum':
        checkMaximum(value as number, instance, path, errors);
        break;
      case 'exclusiveMinimum':
        checkExclusiveMinimum(value as number, instance, path, errors);
        break;
      case 'exclusiveMaximum':
        checkExclusiveMaximum(value as number, instance, path, errors);
        break;
      case 'format':
        checkFormat(value as string, instance, path, errors, ctx);
        break;
      case 'allOf':
        checkAllOf(value as unknown[], instance, path, errors, ctx);
        break;
      case 'oneOf':
        checkOneOf(value as unknown[], instance, path, errors, ctx);
        break;
      case '$ref':
        checkRef(value as string, instance, path, errors, ctx);
        break;
      case 'if':
        checkIfThenElse(s, instance, path, errors, ctx);
        break;
      // `then` / `else` are handled by the `if` branch; skip when seen directly.
      case 'then':
      case 'else':
        break;
      default:
        // Annotation / unsupported keyword: ignored (jsonschema ignores unknown
        // keywords). `$schema`, `$id`, `title`, `description`, `examples`,
        // `$comment` fall here, matching jsonschema's no-op handling.
        break;
    }
    // Stamp CPython's `error._set(validator=k, validator_value=v, schema=s)`:
    // every error a keyword check pushed DIRECTLY (no `keyword` field yet)
    // belongs to this keyword. Errors that bubbled up from a DESCENDED
    // validateNode were already stamped by their own (innermost) keyword loop
    // — exactly CPython's behavior, where `descend` preserves the leaf
    // validator and only extends the paths.
    for (let i = errorCountBefore; i < errors.length; i += 1) {
      const error = errors[i];
      if (error !== undefined && !('keyword' in error)) {
        error.keyword = keyword;
        error.validatorValue = value;
        error.schema = s;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// JSON-type helpers (Python `jsonschema` type semantics)
// ---------------------------------------------------------------------------

/**
 * Map a JS value to its JSON-Schema type name set, matching Draft 2020-12 +
 * CPython jsonschema's defaults:
 * - `boolean` is its OWN type and is NOT an `integer`/`number` (jsonschema does
 *   not treat `True`/`False` as numbers).
 * - an `integer`-valued number is both `number` AND `integer`; a fractional
 *   number is only `number`.
 * - `null`, `string`, `array`, `object` map directly.
 */
function jsonTypeMatches(value: unknown, typeName: string): boolean {
  switch (typeName) {
    case 'null':
      return value === null;
    case 'boolean':
      return typeof value === 'boolean';
    case 'string':
      return typeof value === 'string';
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'number':
      return typeof value === 'number';
    case 'array':
      return Array.isArray(value);
    case 'object':
      return isPlainObject(value);
    default:
      return false;
  }
}

/** Python `isinstance(x, dict)`: a plain object, not an array / null. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// Keyword checks (each pushes CPython-jsonschema-identical messages)
// ---------------------------------------------------------------------------

function checkType(
  type: unknown,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  const types = Array.isArray(type) ? (type as string[]) : [type as string];
  if (types.some((t) => jsonTypeMatches(instance, t))) {
    return;
  }
  // CPython renders a UNION as the per-type reprs joined by ", "
  // (`is not of type 'string', 'null'`), a single type as just its repr.
  const rendered = types.map((t) => pyRepr(t)).join(', ');
  errors.push({
    jsonPath: path,
    message: `${pyRepr(instance)} is not of type ${rendered}`,
  });
}

function checkEnum(
  allowed: unknown[],
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (allowed.some((a) => deepEqual(a, instance))) {
    return;
  }
  errors.push({
    jsonPath: path,
    message: `${pyRepr(instance)} is not one of ${pyReprList(allowed)}`,
  });
}

function checkConst(
  expected: unknown,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (deepEqual(expected, instance)) {
    return;
  }
  errors.push({
    jsonPath: path,
    message: `${pyRepr(expected)} was expected`,
  });
}

function checkRequired(
  required: string[],
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (!isPlainObject(instance)) {
    return; // `required` only applies to objects
  }
  // CPython yields one error per missing property, in the schema's `required`
  // array order.
  for (const prop of required) {
    if (!(prop in instance)) {
      errors.push({
        jsonPath: path,
        message: `${pyRepr(prop)} is a required property`,
      });
    }
  }
}

function checkProperties(
  properties: Record<string, unknown>,
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  if (!isPlainObject(instance)) {
    return;
  }
  // CPython descends in the SCHEMA's `properties` declaration order (NOT the
  // instance order) and only for keys present in the instance.
  for (const prop of Object.keys(properties)) {
    if (prop in instance) {
      validateNode(
        properties[prop],
        instance[prop],
        `${path}${childPath(prop)}`,
        errors,
        ctx,
      );
    }
  }
}

function checkAdditionalProperties(
  schema: Record<string, unknown>,
  additional: unknown,
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  if (!isPlainObject(instance)) {
    return;
  }
  const extras = findAdditionalProperties(instance, schema);
  if (additional === false) {
    if (extras.length === 0) {
      return;
    }
    // CPython: sorted(extras, key=str), joined by ", ", verb agreement.
    const sorted = [...extras].sort(strCompare);
    const joined = sorted.map(pyRepr).join(', ');
    const verb = sorted.length === 1 ? 'was' : 'were';
    errors.push({
      jsonPath: path,
      message: `Additional properties are not allowed (${joined} ${verb} unexpected)`,
    });
    return;
  }
  if (additional === true || additional === undefined) {
    return; // anything allowed
  }
  // additionalProperties is a subschema: validate every extra against it.
  for (const key of extras) {
    validateNode(
      additional,
      instance[key],
      `${path}${childPath(key)}`,
      errors,
      ctx,
    );
  }
}

function checkPatternProperties(
  patternProps: Record<string, unknown>,
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  if (!isPlainObject(instance)) {
    return;
  }
  for (const pattern of Object.keys(patternProps)) {
    const re = new RegExp(pattern);
    for (const key of Object.keys(instance)) {
      if (re.test(key)) {
        validateNode(
          patternProps[pattern],
          instance[key],
          `${path}${childPath(key)}`,
          errors,
          ctx,
        );
      }
    }
  }
}

function checkItems(
  itemsSchema: unknown,
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  if (!Array.isArray(instance)) {
    return;
  }
  // Draft 2020-12 `items` (schema form) applies to every element.
  instance.forEach((element, i) => {
    validateNode(itemsSchema, element, `${path}[${i}]`, errors, ctx);
  });
}

function checkContains(
  containsSchema: unknown,
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  if (!Array.isArray(instance)) {
    return;
  }
  // CPython: at least one element must match. If none do, ONE error at the array
  // path. The element sub-errors are NOT surfaced (jsonschema discards them).
  const anyMatch = instance.some(
    (element) => iterErrorsSilent(containsSchema, element, ctx).length === 0,
  );
  if (!anyMatch) {
    errors.push({
      jsonPath: path,
      message: `${pyRepr(instance)} does not contain items matching the given schema`,
    });
  }
}

function checkMinItems(
  limit: number,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (!Array.isArray(instance) || instance.length >= limit) {
    return;
  }
  // CPython: minItems == 1 -> "should be non-empty"; else "is too short".
  const message =
    limit === 1
      ? `${pyRepr(instance)} should be non-empty`
      : `${pyRepr(instance)} is too short`;
  errors.push({ jsonPath: path, message });
}

function checkMaxItems(
  limit: number,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (!Array.isArray(instance) || instance.length <= limit) {
    return;
  }
  errors.push({ jsonPath: path, message: `${pyRepr(instance)} is too long` });
}

function checkMinLength(
  limit: number,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (typeof instance !== 'string' || codePointLength(instance) >= limit) {
    return;
  }
  const message =
    limit === 1
      ? `${pyRepr(instance)} should be non-empty`
      : `${pyRepr(instance)} is too short`;
  errors.push({ jsonPath: path, message });
}

function checkMaxLength(
  limit: number,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (typeof instance !== 'string' || codePointLength(instance) <= limit) {
    return;
  }
  errors.push({ jsonPath: path, message: `${pyRepr(instance)} is too long` });
}

function checkPattern(
  pattern: string,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (typeof instance !== 'string') {
    return;
  }
  // Python `re.search` semantics (unanchored search). The schemas anchor with
  // ^...$ explicitly, so `search` vs `match` does not differ here.
  if (new RegExp(pattern).test(instance)) {
    return;
  }
  errors.push({
    jsonPath: path,
    message: `${pyRepr(instance)} does not match ${pyRepr(pattern)}`,
  });
}

function checkMinimum(
  limit: number,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (!isComparableNumber(instance) || instance >= limit) {
    return;
  }
  errors.push({
    jsonPath: path,
    message: `${pyRepr(instance)} is less than the minimum of ${pyRepr(limit)}`,
  });
}

function checkMaximum(
  limit: number,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (!isComparableNumber(instance) || instance <= limit) {
    return;
  }
  errors.push({
    jsonPath: path,
    message: `${pyRepr(instance)} is greater than the maximum of ${pyRepr(limit)}`,
  });
}

function checkExclusiveMinimum(
  limit: number,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (!isComparableNumber(instance) || instance > limit) {
    return;
  }
  errors.push({
    jsonPath: path,
    message: `${pyRepr(instance)} is less than or equal to the minimum of ${pyRepr(limit)}`,
  });
}

function checkExclusiveMaximum(
  limit: number,
  instance: unknown,
  path: string,
  errors: SchemaError[],
): void {
  if (!isComparableNumber(instance) || instance < limit) {
    return;
  }
  errors.push({
    jsonPath: path,
    message: `${pyRepr(instance)} is greater than or equal to the maximum of ${pyRepr(limit)}`,
  });
}

function checkFormat(
  format: string,
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  // CPython jsonschema only asserts `format` when a `format_checker` is passed.
  // Non-string instances are skipped here (the custom Concordia checkers return
  // `True` for non-strings, deferring to the `type` keyword).
  if (ctx.formatChecker === undefined || typeof instance !== 'string') {
    return;
  }
  if (ctx.formatChecker(format, instance)) {
    return;
  }
  errors.push({
    jsonPath: path,
    message: `${pyRepr(instance)} is not a ${pyRepr(format)}`,
  });
}

function checkAllOf(
  branches: unknown[],
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  // CPython yields the sub-errors of EVERY failing branch, in branch order.
  for (const branch of branches) {
    validateNode(branch, instance, path, errors, ctx);
  }
}

function checkOneOf(
  branches: unknown[],
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  const matches = branches.filter(
    (branch) => iterErrorsSilent(branch, instance, ctx).length === 0,
  );
  if (matches.length === 1) {
    return;
  }
  if (matches.length === 0) {
    errors.push({
      jsonPath: path,
      message: `${pyRepr(instance)} is not valid under any of the given schemas`,
    });
    return;
  }
  errors.push({
    jsonPath: path,
    message: `${pyRepr(instance)} is valid under each of ${branches
      .map(pyRepr)
      .join(', ')}`,
  });
}

function checkRef(
  ref: string,
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  if (ctx.refStack.has(ref)) {
    throw new Error(`schema-validator: cyclic $ref ${pyRepr(ref)}`);
  }
  ctx.refStack.add(ref);
  try {
    const target = resolveJsonPointerRef(ctx.rootSchema, ref);
    validateNode(target, instance, path, errors, ctx);
  } finally {
    ctx.refStack.delete(ref);
  }
}

function checkIfThenElse(
  schema: Record<string, unknown>,
  instance: unknown,
  path: string,
  errors: SchemaError[],
  ctx: ValidationContext,
): void {
  // Draft 2020-12 if/then/else: if `if` validates, apply `then`; else apply
  // `else`. The `if` keyword itself produces NO errors (it is a condition).
  const ifSchema = schema.if;
  const ifValid = iterErrorsSilent(ifSchema, instance, ctx).length === 0;
  if (ifValid) {
    if ('then' in schema) {
      validateNode(schema.then, instance, path, errors, ctx);
    }
  } else if ('else' in schema) {
    validateNode(schema.else, instance, path, errors, ctx);
  }
}

// ---------------------------------------------------------------------------
// Internal utilities
// ---------------------------------------------------------------------------

/**
 * Validate without recording into the caller's list — used by `contains` and
 * `if` where only the pass/fail boolean matters (CPython discards the sub-errors
 * of these applicators).
 */
function iterErrorsSilent(
  schema: unknown,
  instance: unknown,
  ctx: ValidationContext,
): SchemaError[] {
  const local: SchemaError[] = [];
  validateNode(schema, instance, '$', local, ctx);
  return local;
}

function resolveJsonPointerRef(root: unknown, ref: string): unknown {
  if (!ref.startsWith('#/')) {
    throw new Error(
      `schema-validator: unsupported $ref ${pyRepr(ref)}; only intra-document JSON Pointer refs are supported`,
    );
  }
  let current = root;
  for (const rawPart of ref.slice(2).split('/')) {
    if (/~(?![01])/.test(rawPart)) {
      throw new Error(`schema-validator: malformed $ref ${pyRepr(ref)}`);
    }
    const part = rawPart.replace(/~1/g, '/').replace(/~0/g, '~');
    if (isPlainObject(current) && part in current) {
      current = current[part];
      continue;
    }
    throw new Error(`schema-validator: unresolved $ref ${pyRepr(ref)}`);
  }
  return current;
}

/**
 * CPython jsonschema `find_additional_properties`: instance keys not present in
 * `properties` and not matched by any `patternProperties` regex.
 */
function findAdditionalProperties(
  instance: Record<string, unknown>,
  schema: Record<string, unknown>,
): string[] {
  const props =
    (schema.properties as Record<string, unknown> | undefined) ?? {};
  const patternProps =
    (schema.patternProperties as Record<string, unknown> | undefined) ?? {};
  const patternKeys = Object.keys(patternProps);
  const joined =
    patternKeys.length > 0 ? new RegExp(patternKeys.join('|')) : null;
  return Object.keys(instance).filter((key) => {
    if (key in props) return false;
    if (joined && joined.test(key)) return false;
    return true;
  });
}

/** Build the `json_path` segment for a child key (`.key` or `['key']`). */
function childPath(key: string): string {
  // CPython jsonschema's `json_path` uses `.key` for identifier-like keys and
  // `['key']` for keys that are not valid bare identifiers (contain non
  // word-chars or are numeric). The Concordia schemas only have identifier-like
  // property names, but reproduce the rule for completeness.
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    return `.${key}`;
  }
  // Non-identifier key: CPython uses `[<repr>]`.
  return `[${pyRepr(key)}]`;
}

/** CPython list repr for the `enum` keyword: `[repr(a), repr(b), ...]`. */
function pyReprList(values: unknown[]): string {
  return `[${values.map(pyRepr).join(', ')}]`;
}

/** `sorted(..., key=str)` ordering: lexicographic by string value. */
function strCompare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * A number eligible for the numeric-bound keywords. Excludes booleans (Python
 * jsonschema's numeric keywords skip `True`/`False`, since `bool` is not treated
 * as a `number` instance for `minimum`/`maximum` application).
 */
function isComparableNumber(value: unknown): value is number {
  return typeof value === 'number';
}

/**
 * Length by CODE POINTS (Python `len(str)` counts code points, not UTF-16 code
 * units), so an astral character counts as one — matching CPython's minLength /
 * maxLength.
 */
function codePointLength(s: string): number {
  let count = 0;
  for (const _ of s) {
    count += 1;
    void _;
  }
  return count;
}

/**
 * Structural equality for `enum`/`const`, matching CPython jsonschema's equality
 * (which uses Python `==` on the parsed JSON values). Numbers, strings, bools,
 * null compare by value; arrays element-wise in order; objects key-set-equal
 * with equal values (order-independent). `1 == 1.0` is true in Python, and JSON
 * numbers collapse to one JS number, so numeric equality is plain `===` here.
 */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) {
    // Python `1 == True` is true, but JSON `true`/`1` are distinct JS types and
    // the schemas never rely on cross-type equality, so treat differing JS types
    // as unequal (matches the instance space: parsed JSON).
    return false;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const ak = Object.keys(a);
    const bk = Object.keys(b);
    if (ak.length !== bk.length) return false;
    return ak.every((k) => k in b && deepEqual(a[k], (b as Record<string, unknown>)[k]));
  }
  return false;
}

/**
 * The JSON Schema keywords this validator implements. Used by
 * {@link assertSupportedSchema} to fail loudly at module load if a bundled
 * schema introduces an unsupported keyword (which would silently under-validate).
 */
const SUPPORTED_KEYWORDS = new Set<string>([
  // applicators / structure
  'type',
  'enum',
  'const',
  'required',
  'properties',
  'additionalProperties',
  'patternProperties',
  'items',
  'contains',
  'allOf',
  'oneOf',
  'if',
  'then',
  'else',
  '$ref',
  '$defs',
  // string / number / array constraints
  'minItems',
  'maxItems',
  'minLength',
  'maxLength',
  'pattern',
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'format',
  // annotations (no-op, allowed)
  '$schema',
  '$id',
  'title',
  'description',
  'examples',
  '$comment',
  'default',
]);

/**
 * Walk a schema and throw if it uses a keyword this validator does NOT support
 * (which would silently under-validate vs CPython jsonschema). Called at module
 * load on each bundled schema so a future schema edit that adds an unported
 * keyword fails fast at import rather than passing invalid instances silently.
 */
export function assertSupportedSchema(schema: unknown, name: string): void {
  // Keywords whose VALUE is a map of {name -> subschema}; the names are arbitrary
  // (property names / pattern strings / def names), NOT keywords, so we recurse
  // into the VALUES but never check the keys.
  const SUBSCHEMA_MAP_KEYWORDS = new Set([
    'properties',
    'patternProperties',
    '$defs',
  ]);
  // Keywords whose value is a single subschema (recurse straight in).
  const SINGLE_SUBSCHEMA_KEYWORDS = new Set([
    'items',
    'contains',
    'additionalProperties',
    'if',
    'then',
    'else',
    'not',
  ]);
  // Keywords whose value is an array of subschemas.
  const SUBSCHEMA_LIST_KEYWORDS = new Set(['allOf', 'anyOf', 'oneOf']);

  const visitSchema = (node: unknown): void => {
    // A boolean schema is fine; a non-object is a leaf (enum value, limit, etc.).
    if (!isPlainObject(node)) {
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      if (!SUPPORTED_KEYWORDS.has(k)) {
        throw new Error(
          `schema-validator: bundled schema '${name}' uses unsupported ` +
            `JSON Schema keyword '${k}'; this validator covers only the ported ` +
            `subset. Add support (and parity fixtures) before bundling it.`,
        );
      }
      // Recurse only into the places where SUBSCHEMAS live, so arbitrary
      // property/def NAMES are never mistaken for keywords.
      if (SUBSCHEMA_MAP_KEYWORDS.has(k) && isPlainObject(v)) {
        for (const sub of Object.values(v)) {
          visitSchema(sub);
        }
      } else if (SINGLE_SUBSCHEMA_KEYWORDS.has(k)) {
        visitSchema(v);
      } else if (SUBSCHEMA_LIST_KEYWORDS.has(k) && Array.isArray(v)) {
        v.forEach(visitSchema);
      }
      // Other keyword values (enum arrays, `required` lists, `type`, limits,
      // pattern strings, `const` literals) are not subschemas; do not recurse.
    }
  };
  visitSchema(schema);
}
