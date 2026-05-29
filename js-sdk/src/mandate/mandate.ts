/**
 * Concordia mandate credential models (data layer).
 *
 * Port of the DATA layer in `concordia/models/mandate.py`. A mandate is a
 * signed credential that authorizes an agent to act within specified
 * constraints on behalf of an issuer. This module ports ONLY the data
 * structures, enums, and their serialization (`to_dict`/`from_dict`); the
 * signing, verification, jsonschema-validation, urllib revocation I/O, and
 * delegation-scope composition engine in `concordia/mandate.py` is DEFERRED to
 * a later PR (it depends on a jsonschema port, network I/O, and the mandate
 * signing path).
 *
 * Cross-language parity is the load-bearing property: each `*.toDict()` here
 * emits the SAME object Python's `to_dict()` does -- identical wire key names
 * (snake_case), identical INSERTION ORDER, identical conditional-omission rules
 * (a key appears only when Python's `if self.x is not None` / truthiness guard
 * fires), and identical `from_dict` default fallbacks. The `Mandate.toDict()`
 * output crosses the wire and will be canonicalized + signed by the deferred
 * engine, so a single divergence (a wrongly-emitted key, a wrong default) would
 * break signature parity once PR 6 lands. Every expectation is asserted against
 * fixtures generated FROM Python (`tests/fixtures/mandate/mandate_vectors.json`).
 */

/**
 * Validity temporal modes aligned with trust-evidence-format v1.0.0.
 * Mirrors Python `TemporalMode`. The string VALUES cross the wire (they appear
 * in `validity.mode` inside the signed mandate dict), so they must be
 * byte-identical to Python's `Enum` member values.
 */
export const TemporalMode = {
  SEQUENCE: 'sequence',
  WINDOWED: 'windowed',
  STATE_BOUND: 'state_bound',
} as const;
export type TemporalMode = (typeof TemporalMode)[keyof typeof TemporalMode];

/**
 * Lifecycle status of a mandate credential. Mirrors Python `MandateStatus`.
 * The VALUES cross the wire (in `status`), so they are byte-identical to
 * Python's `Enum` member values.
 */
export const MandateStatus = {
  ACTIVE: 'active',
  EXPIRED: 'expired',
  REVOKED: 'revoked',
  SUSPENDED: 'suspended',
} as const;
export type MandateStatus = (typeof MandateStatus)[keyof typeof MandateStatus];

// ---------------------------------------------------------------------------
// Delegation link
// ---------------------------------------------------------------------------

/**
 * A single link in a delegation chain. Mirrors the Python `DelegationLink`
 * dataclass. Field names here are the camelCase TS-facing names; the wire
 * (`toDict`) keys are snake_case to match Python exactly.
 */
export interface DelegationLink {
  /** DID or agent_id of the delegator. */
  delegator: string;
  /** DID or agent_id of the delegate. */
  delegate: string;
  /** Narrowing constraints. Python default: `None`. */
  scopeRestriction?: Record<string, unknown> | null;
  /** ISO 8601 timestamp. Python default: `""`. */
  delegatedAt?: string;
  /** base64url EdDSA/ES256 over canonical payload. Python default: `""`. */
  signature?: string;
  /** Python default: `"EdDSA"`. */
  algorithm?: string;
}

/**
 * Construct a {@link DelegationLink} with the same field defaults the Python
 * `DelegationLink` dataclass declares (`scope_restriction=None`,
 * `delegated_at=""`, `signature=""`, `algorithm="EdDSA"`).
 */
export function makeDelegationLink(
  fields: { delegator: string; delegate: string } & Partial<DelegationLink>,
): DelegationLink {
  return {
    scopeRestriction: null,
    delegatedAt: '',
    signature: '',
    algorithm: 'EdDSA',
    ...fields,
  };
}

/**
 * Serialize a {@link DelegationLink} to its wire form.
 *
 * Parity with Python `DelegationLink.to_dict()`: emits `delegator`, `delegate`,
 * `delegated_at`, `signature`, `algorithm` (in that exact order), then appends
 * `scope_restriction` ONLY when it is non-null (Python: `if
 * self.scope_restriction is not None`). The `delegated_at` / `signature` /
 * `algorithm` defaults are supplied here so a partially-specified link
 * serializes identically to a Python dataclass with its field defaults.
 */
export function delegationLinkToDict(
  link: DelegationLink,
): Record<string, unknown> {
  // Python `to_dict` emits these three fields VERBATIM (`self.delegated_at`
  // etc.). The dataclass field can be `None` only when a present-null was read
  // by `from_dict`; in that case Python emits `null` and so must this. The
  // default here is supplied ONLY for a TS-side `undefined` (an optional field a
  // partial object never set) -- it must NOT collapse an explicit `null`, which
  // a `?? default` would wrongly do.
  const d: Record<string, unknown> = {
    delegator: link.delegator,
    delegate: link.delegate,
    delegated_at: link.delegatedAt === undefined ? '' : link.delegatedAt,
    signature: link.signature === undefined ? '' : link.signature,
    algorithm: link.algorithm === undefined ? 'EdDSA' : link.algorithm,
  };
  if (link.scopeRestriction !== undefined && link.scopeRestriction !== null) {
    d.scope_restriction = link.scopeRestriction;
  }
  return d;
}

/**
 * Parse a {@link DelegationLink} from its wire form. Mirrors Python
 * `DelegationLink.from_dict`: `delegator` / `delegate` are required (Python
 * indexes them directly, raising `KeyError` if absent); the rest fall back to
 * the dataclass defaults (`scope_restriction=None`, `delegated_at=""`,
 * `signature=""`, `algorithm="EdDSA"`).
 */
export function delegationLinkFromDict(
  data: Record<string, unknown>,
): DelegationLink {
  if (!('delegator' in data)) {
    throw new MandateValidationError("'delegator'");
  }
  if (!('delegate' in data)) {
    throw new MandateValidationError("'delegate'");
  }
  // Each non-required field mirrors Python `data.get(key, default)`: the default
  // applies ONLY when the key is ABSENT. A key PRESENT with `null` keeps `null`
  // (Python `data.get(...)` returns the present None), so an explicit-null
  // round-trips byte-identically rather than collapsing to the default.
  return {
    delegator: data.delegator as string,
    delegate: data.delegate as string,
    scopeRestriction: pyGet(data, 'scope_restriction', null) as
      | Record<string, unknown>
      | null,
    delegatedAt: pyGet(data, 'delegated_at', '') as string,
    signature: pyGet(data, 'signature', '') as string,
    algorithm: pyGet(data, 'algorithm', 'EdDSA') as string,
  };
}

/**
 * Mirror of Python `dict.get(key, default)`: return the value VERBATIM (including
 * an explicit `null`) when the key is PRESENT, otherwise the `default`. This is
 * the load-bearing distinction the `from_dict` ports rely on -- a key-present
 * `null` must NOT be replaced by the dataclass default (which a `?? default`
 * would wrongly do), because Python keeps the present `None` and serializes it
 * back out verbatim. Key-ABSENT alone triggers the default.
 */
function pyGet(
  data: Record<string, unknown>,
  key: string,
  fallback: unknown,
): unknown {
  return key in data ? data[key] : fallback;
}

// ---------------------------------------------------------------------------
// Validity window
// ---------------------------------------------------------------------------

/**
 * Temporal validity for a mandate. Mirrors the Python `ValidityWindow`
 * dataclass. Three modes (sequence / windowed / state_bound) per
 * {@link TemporalMode}.
 */
export interface ValidityWindow {
  mode: TemporalMode;
  /** ISO 8601 (windowed mode). Python default: `None`. */
  notBefore?: string | null;
  /** ISO 8601 (windowed mode). Python default: `None`. */
  notAfter?: string | null;
  /** Opaque key (sequence mode). Python default: `None`. */
  sequenceKey?: string | null;
  /** Named condition (state_bound mode). Python default: `None`. */
  stateCondition?: string | null;
  /** Optional use count limit. Python default: `None`. */
  maxUses?: number | null;
}

/**
 * Construct a {@link ValidityWindow} with the same optional-field defaults the
 * Python `ValidityWindow` dataclass declares (all optional fields `None`).
 */
export function makeValidityWindow(
  fields: { mode: TemporalMode } & Partial<ValidityWindow>,
): ValidityWindow {
  return {
    notBefore: null,
    notAfter: null,
    sequenceKey: null,
    stateCondition: null,
    maxUses: null,
    ...fields,
  };
}

/**
 * Serialize a {@link ValidityWindow} to its wire form.
 *
 * Parity with Python `ValidityWindow.to_dict()`: always emits `mode` first
 * (the enum VALUE), then appends each optional field IN ORDER (`not_before`,
 * `not_after`, `sequence_key`, `state_condition`, `max_uses`) ONLY when it is
 * non-null (Python guards each with `if self.x is not None`).
 */
export function validityWindowToDict(
  validity: ValidityWindow,
): Record<string, unknown> {
  const d: Record<string, unknown> = { mode: validity.mode };
  if (validity.notBefore !== undefined && validity.notBefore !== null) {
    d.not_before = validity.notBefore;
  }
  if (validity.notAfter !== undefined && validity.notAfter !== null) {
    d.not_after = validity.notAfter;
  }
  if (validity.sequenceKey !== undefined && validity.sequenceKey !== null) {
    d.sequence_key = validity.sequenceKey;
  }
  if (
    validity.stateCondition !== undefined &&
    validity.stateCondition !== null
  ) {
    d.state_condition = validity.stateCondition;
  }
  if (validity.maxUses !== undefined && validity.maxUses !== null) {
    d.max_uses = validity.maxUses;
  }
  return d;
}

/**
 * Parse a {@link ValidityWindow} from its wire form. Mirrors Python
 * `ValidityWindow.from_dict`: `mode` is required and passed through
 * `TemporalMode(...)` (raising on an unknown value, exactly as Python's
 * `TemporalMode(data["mode"])` raises `ValueError`); the rest fall back to
 * `None`.
 */
export function validityWindowFromDict(
  data: Record<string, unknown>,
): ValidityWindow {
  if (!('mode' in data)) {
    throw new MandateValidationError("'mode'");
  }
  const modeValue = data.mode;
  if (!isTemporalMode(modeValue)) {
    // Mirror Python `TemporalMode(value)` raising ValueError on an unknown
    // member value.
    throw new MandateValidationError(
      `${pyRepr(modeValue)} is not a valid TemporalMode`,
    );
  }
  return {
    mode: modeValue,
    notBefore: (data.not_before as string) ?? null,
    notAfter: (data.not_after as string) ?? null,
    sequenceKey: (data.sequence_key as string) ?? null,
    stateCondition: (data.state_condition as string) ?? null,
    maxUses: (data.max_uses as number) ?? null,
  };
}

function isTemporalMode(value: unknown): value is TemporalMode {
  return (
    value === TemporalMode.SEQUENCE ||
    value === TemporalMode.WINDOWED ||
    value === TemporalMode.STATE_BOUND
  );
}

function isMandateStatus(value: unknown): value is MandateStatus {
  return (
    value === MandateStatus.ACTIVE ||
    value === MandateStatus.EXPIRED ||
    value === MandateStatus.REVOKED ||
    value === MandateStatus.SUSPENDED
  );
}

/**
 * Render a value the way CPython's `repr()` would, so the enum-`ValueError`
 * text is BYTE-IDENTICAL to Python's `f"{value!r} is not a valid TemporalMode"`.
 *
 * The `mode` value reaching this path is the wire dict's `data["mode"]`, i.e.
 * any JSON-shaped value (string, number, boolean, null, array, object), possibly
 * nested. Python's `repr()` quotes strings, renders `None`/`True`/`False`, and
 * reprs list / dict elements RECURSIVELY with `[a, b]` / `{k: v}` spacing -- e.g.
 * `mode=[]` gives `"[] is not a valid TemporalMode"` (not JS `String([])` ->
 * `""`), and `mode={}` gives `"{} is not a valid TemporalMode"` (not
 * `"[object Object]"`). This reproduces CPython `repr()` for that value space.
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
    // dict: `{repr(k): repr(v), ...}` in insertion order, recursive.
    const inner = Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${pyRepr(k)}: ${pyRepr(v)}`)
      .join(', ');
    return `{${inner}}`;
  }
  // Any other JS type (symbol, function) cannot appear in a JSON-shaped wire
  // value; fall back to String() so the helper is still total.
  return String(value);
}

/**
 * CPython `repr()` of a `str`, byte-identical to `unicode_repr` in CPython.
 *
 * Quote selection: CPython quotes with `'` by default, but switches to `"` when
 * the string contains a `'` AND no `"`. The active quote and `\` are
 * backslash-escaped inside; `\t` / `\n` / `\r` use their named escapes; every
 * other non-"printable" code point (CPython `str.isprintable()`, i.e. NOT in
 * Unicode categories Cc/Cf/Cs/Co/Cn/Zl/Zp/Zs, with ASCII space 0x20 the one
 * printable separator) escapes as `\xNN` (cp < 0x100), `\uNNNN` (< 0x10000), or
 * `\UNNNNNNNN` (astral), lowercase hex, fixed width. Iterates by CODE POINT
 * (`[...s]`) so astral chars get one `\U........` escape, not two surrogate
 * halves -- matching CPython, which reprs by code point.
 */
function pyReprString(s: string): string {
  // CPython: default single-quote; use double only when a single-quote is
  // present and a double-quote is absent.
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

/**
 * Non-printable code points per CPython `str.isprintable()`: any character whose
 * Unicode general category is Other (Cc control, Cf format, Cs surrogate, Co
 * private-use, Cn unassigned) or Separator (Zl line, Zp paragraph, Zs space),
 * EXCEPT ASCII space 0x20 which CPython treats as printable.
 *
 * KNOWN PARITY RESIDUAL (accepted 2026-05-29, fail-CLOSED + unreachable): this
 * uses the JS runtime's Unicode tables (\p{...}), which can disagree with
 * CPython's Unicode database VERSION at the printability boundary for some
 * UNASSIGNED astral code points (e.g. U+3203F: Node may treat printable while
 * CPython escapes it). It only affects the repr() ERROR TEXT of an INVALID
 * TemporalMode value that is such a code point — a value that is rejected
 * either way (no fail-open) and never occurs as a real mode (modes are a tiny
 * ASCII enum). Full closure would require pinning a Unicode-DB version to
 * CPython's, which is brittle and not worth it; deferred.
 */
const NON_PRINTABLE_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

/** True when CPython `str.isprintable()` would treat this code point as printable. */
function isPyPrintable(ch: string, cp: number): boolean {
  if (cp === 0x20) return true; // ASCII space: the lone printable separator.
  return !NON_PRINTABLE_RE.test(ch);
}

/**
 * CPython `repr()` of a number reaching the enum path. The `mode` value is
 * JSON-shaped, and JSON carries no int/float tag, so a wire `100.0` and `100`
 * BOTH parse to a JS `number` that `repr()`s as the integer `100` on either
 * side (Python `json.loads("100.0")` -> int via the same collapse) -- so an
 * integer-valued finite number reprs WITHOUT a trailing `.0`, matching the
 * value space that can actually arrive. The only floats that cannot be
 * JSON-sourced are the non-finite ones (an in-memory JS value, never parsed
 * JSON): CPython reprs those as `nan` / `inf` / `-inf`, which JS `String()`
 * would wrongly render as `NaN` / `Infinity` / `-Infinity`, so map them
 * explicitly. Finite non-integers (e.g. `1.5`) match JS `String()` for the
 * decimal forms that survive a JSON round-trip.
 */
function pyReprNumber(n: number): string {
  if (Number.isNaN(n)) return 'nan';
  if (n === Infinity) return 'inf';
  if (n === -Infinity) return '-inf';
  return String(n);
}

// ---------------------------------------------------------------------------
// Mandate credential
// ---------------------------------------------------------------------------

/**
 * A signed credential authorizing an agent to act within constraints. Mirrors
 * the Python `Mandate` dataclass. TS-facing field names are camelCase; the wire
 * (`toDict`) keys are snake_case to match Python exactly.
 */
export interface Mandate {
  /** Unique identifier (URN format). Python default: `""`. */
  mandateId: string;
  /** DID or agent_id of the mandate issuer. Python default: `""`. */
  issuer: string;
  /** DID or agent_id of the authorized agent. Python default: `""`. */
  subject: string;
  /** ISO 8601 timestamp of issuance. Python default: `""`. */
  issuedAt: string;
  /** Temporal validity window. Python default: `None`. */
  validity?: ValidityWindow | null;
  /** JSON Schema dict defining what the mandate authorizes. Python default: `{}`. */
  constraints: Record<string, unknown>;
  /** Ordered list of delegation links (root -> holder). Python default: `[]`. */
  delegationChain: DelegationLink[];
  /** Optional URL to check revocation status. Python default: `None`. */
  revocationEndpoint?: string | null;
  /** ISO 8601 revocation timestamp set by a resolver. Python default: `None`. */
  revokedAt?: string | null;
  /** Additional key-value pairs. Python default: `{}`. */
  metadata: Record<string, unknown>;
  /** Base64url signature over all fields except signature itself. Python default: `""`. */
  signature: string;
  /** Signing algorithm ("EdDSA" or "ES256"). Python default: `"EdDSA"`. */
  algorithm: string;
  /** Current mandate status. Python default: `MandateStatus.ACTIVE`. */
  status: MandateStatus;
}

/**
 * Construct a {@link Mandate} with the same field defaults the Python `Mandate`
 * dataclass declares (`mandate_id=""`, `issuer=""`, `subject=""`,
 * `issued_at=""`, `validity=None`, `constraints={}`, `delegation_chain=[]`,
 * `revocation_endpoint=None`, `revoked_at=None`, `metadata={}`, `signature=""`,
 * `algorithm="EdDSA"`, `status=MandateStatus.ACTIVE`).
 */
export function makeMandate(overrides: Partial<Mandate> = {}): Mandate {
  return {
    mandateId: '',
    issuer: '',
    subject: '',
    issuedAt: '',
    validity: null,
    constraints: {},
    delegationChain: [],
    revocationEndpoint: null,
    revokedAt: null,
    metadata: {},
    signature: '',
    algorithm: 'EdDSA',
    status: MandateStatus.ACTIVE,
    ...overrides,
  };
}

/**
 * Serialize a {@link Mandate} to its wire form (the canonical form the deferred
 * signing engine will sign over).
 *
 * Parity with Python `Mandate.to_dict()` is exact and load-bearing:
 *   1. The SIX always-present keys are emitted first, in this order:
 *      `mandate_id`, `issuer`, `subject`, `issued_at`, `algorithm`,
 *      `status` (the enum VALUE). Note `algorithm` and `status` precede the
 *      conditional block, matching Python's insertion order.
 *   2. Then each conditional key is appended IN ORDER, each behind the SAME
 *      guard Python uses:
 *        - `validity`           if `validity is not None`
 *        - `constraints`        if `self.constraints` is TRUTHY (non-empty dict)
 *        - `delegation_chain`   if `self.delegation_chain` is TRUTHY (non-empty)
 *        - `revocation_endpoint` if `revocation_endpoint is not None`
 *        - `revoked_at`         if `revoked_at is not None`
 *        - `metadata`           if `self.metadata` is TRUTHY (non-empty dict)
 *        - `signature`          if `self.signature` is TRUTHY (non-empty string)
 *
 * The truthiness vs not-None distinction matters: an EMPTY `constraints` /
 * `metadata` / `delegation_chain` is OMITTED (Python `if self.constraints:`),
 * whereas an empty-string `revocation_endpoint`/`revoked_at` would be EMITTED
 * (Python `if x is not None`). This function reproduces each guard exactly.
 */
export function mandateToDict(mandate: Mandate): Record<string, unknown> {
  const d: Record<string, unknown> = {
    mandate_id: mandate.mandateId,
    issuer: mandate.issuer,
    subject: mandate.subject,
    issued_at: mandate.issuedAt,
    algorithm: mandate.algorithm,
    status: mandate.status,
  };
  if (mandate.validity !== undefined && mandate.validity !== null) {
    d.validity = validityWindowToDict(mandate.validity);
  }
  // Python `if self.constraints:` -- truthy guard, omits an empty dict.
  if (isNonEmptyObject(mandate.constraints)) {
    d.constraints = mandate.constraints;
  }
  // Python `if self.delegation_chain:` -- truthy guard, omits an empty list.
  if (mandate.delegationChain.length > 0) {
    d.delegation_chain = mandate.delegationChain.map(delegationLinkToDict);
  }
  if (
    mandate.revocationEndpoint !== undefined &&
    mandate.revocationEndpoint !== null
  ) {
    d.revocation_endpoint = mandate.revocationEndpoint;
  }
  if (mandate.revokedAt !== undefined && mandate.revokedAt !== null) {
    d.revoked_at = mandate.revokedAt;
  }
  // Python `if self.metadata:` -- truthy guard, omits an empty dict.
  if (isNonEmptyObject(mandate.metadata)) {
    d.metadata = mandate.metadata;
  }
  // Python `if self.signature:` -- truthy guard, omits an empty string.
  if (mandate.signature) {
    d.signature = mandate.signature;
  }
  return d;
}

/**
 * True for a plain object with at least one own key (mirrors Python dict
 * truthiness). A `null` value is falsy (Python `if None:` is False), so an
 * explicit-null `constraints`/`metadata` from a present-null `from_dict` is
 * OMITTED -- matching Python, where `data.get("constraints", {})` returns the
 * present `None` and `if self.constraints:` then drops the key.
 */
function isNonEmptyObject(value: Record<string, unknown> | null): boolean {
  return value != null && Object.keys(value).length > 0;
}

/**
 * Parse a {@link Mandate} from its wire form. Mirrors Python `Mandate.from_dict`:
 *   - `validity` is parsed via {@link validityWindowFromDict} ONLY when the
 *     `validity` key is present (Python `if "validity" in data`).
 *   - `delegation_chain` entries are each parsed via
 *     {@link delegationLinkFromDict} ONLY when the key is present.
 *   - `status` is read through the enum, and an UNKNOWN status value falls back
 *     to `ACTIVE` (Python catches `ValueError` and defaults to ACTIVE) -- this
 *     is the fail-SAFE behavior the Python reference chose; reproduce it
 *     exactly rather than raising.
 *   - every scalar field falls back to its dataclass default
 *     (`data.get(k, default)`).
 */
export function mandateFromDict(data: Record<string, unknown>): Mandate {
  let validity: ValidityWindow | null = null;
  if ('validity' in data) {
    validity = validityWindowFromDict(
      data.validity as Record<string, unknown>,
    );
  }

  let chain: DelegationLink[] = [];
  if ('delegation_chain' in data) {
    chain = (data.delegation_chain as Record<string, unknown>[]).map(
      delegationLinkFromDict,
    );
  }

  // Python: try MandateStatus(data["status"]) except ValueError -> ACTIVE.
  // A present-but-unknown status value silently defaults to ACTIVE (fail-safe
  // per the Python reference); an ABSENT status also defaults to ACTIVE.
  let status: MandateStatus = MandateStatus.ACTIVE;
  if ('status' in data && isMandateStatus(data.status)) {
    status = data.status;
  }

  // Every scalar/collection field mirrors Python `data.get(key, default)` via
  // {@link pyGet}: the dataclass default applies ONLY when the key is ABSENT. A
  // key PRESENT with `null` keeps `null` verbatim (Python keeps the present
  // None). For the six always-emitted keys (mandate_id/issuer/subject/issued_at/
  // algorithm) a present-null survives all the way through to_dict; for
  // truthiness-guarded fields (constraints/metadata/signature) a present-null is
  // kept here and then OMITTED by to_dict's `if x:` guard -- exactly as Python.
  return {
    mandateId: pyGet(data, 'mandate_id', '') as string,
    issuer: pyGet(data, 'issuer', '') as string,
    subject: pyGet(data, 'subject', '') as string,
    issuedAt: pyGet(data, 'issued_at', '') as string,
    validity,
    constraints: pyGet(data, 'constraints', {}) as Record<string, unknown>,
    delegationChain: chain,
    revocationEndpoint: pyGet(data, 'revocation_endpoint', null) as
      | string
      | null,
    revokedAt: pyGet(data, 'revoked_at', null) as string | null,
    metadata: pyGet(data, 'metadata', {}) as Record<string, unknown>,
    signature: pyGet(data, 'signature', '') as string,
    algorithm: pyGet(data, 'algorithm', 'EdDSA') as string,
    status,
  };
}

/**
 * Source of `now` (ISO 8601) and the unique id used by {@link createMandate}.
 * Injectable so callers (and tests) can pin the otherwise non-deterministic
 * pieces; defaults reproduce Python `Mandate.create`'s
 * `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")` and
 * `urn:concordia:mandate:{uuid4()}`.
 */
export interface CreateMandateClock {
  /** Returns the issuance timestamp as `YYYY-MM-DDTHH:MM:SSZ`. */
  now?: () => string;
  /** Returns a UUID string (the part after `urn:concordia:mandate:`). */
  uuid?: () => string;
}

/**
 * Factory mirroring Python `Mandate.create`: builds a new mandate with an
 * auto-generated URN id (`urn:concordia:mandate:{uuid4}`) and an `issued_at`
 * timestamp in Python's exact `"%Y-%m-%dT%H:%M:%SZ"` UTC format. Optional
 * fields default exactly as Python (`delegation_chain=[]`, `metadata={}`,
 * `revocation_endpoint=None`, `algorithm="EdDSA"`).
 *
 * The uuid + timestamp are inherently non-deterministic, so this factory does
 * NOT participate in byte-parity fixtures; the deterministic SHAPE (URN prefix,
 * timestamp format) is asserted in the tests instead. Supply
 * {@link CreateMandateClock} to make output reproducible.
 */
export function createMandate(
  params: {
    issuer: string;
    subject: string;
    constraints: Record<string, unknown>;
    validity: ValidityWindow;
    revocationEndpoint?: string | null;
    metadata?: Record<string, unknown> | null;
    delegationChain?: DelegationLink[] | null;
    algorithm?: string;
  },
  clock: CreateMandateClock = {},
): Mandate {
  const uuid = clock.uuid ? clock.uuid() : cryptoRandomUuid();
  const now = clock.now ? clock.now() : isoNowUtcSeconds();
  return makeMandate({
    mandateId: `urn:concordia:mandate:${uuid}`,
    issuer: params.issuer,
    subject: params.subject,
    issuedAt: now,
    validity: params.validity,
    constraints: params.constraints,
    delegationChain: params.delegationChain ?? [],
    revocationEndpoint: params.revocationEndpoint ?? null,
    metadata: params.metadata ?? {},
    algorithm: params.algorithm ?? 'EdDSA',
  });
}

/** UTC `now` in Python's `"%Y-%m-%dT%H:%M:%SZ"` format (second resolution). */
function isoNowUtcSeconds(): string {
  // toISOString() yields e.g. "2026-05-29T12:34:56.789Z"; Python's strftime
  // truncates to whole seconds with a trailing Z. Slice to "...T..:..:.." and
  // append "Z".
  return new Date().toISOString().slice(0, 19) + 'Z';
}

/**
 * A v4 UUID string, matching the textual shape Python's `uuid.uuid4()`
 * produces (`8-4-4-4-12` lowercase hex). Uses the platform `crypto.randomUUID`,
 * available in the Node runtime the SDK already targets (it depends on
 * `@noble/curves` and `node:` built-ins).
 */
function cryptoRandomUuid(): string {
  // `crypto` is a global in Node >= 20 (the SDK's declared engine floor) and a
  // Web standard, exposing the Web Crypto `randomUUID()`.
  return crypto.randomUUID();
}

// ---------------------------------------------------------------------------
// Verification result (data carrier only -- verification logic is in PR 6)
// ---------------------------------------------------------------------------

/**
 * Result of mandate verification. Mirrors the Python
 * `MandateVerificationResult` dataclass. This PR ports ONLY the data carrier
 * and its `toDict()`; the engine that POPULATES it
 * (`verify_mandate` / `verify_mandate_with_resolver`) is deferred. The optional
 * resolver fields (`mandate`, `failureReason`, `revokedAt`, `tier`) are carried
 * so the shape is complete for the future engine.
 */
export interface MandateVerificationResult {
  valid: boolean;
  /** Python default: `""`. */
  mandateId: string;
  /** Python default: `""`. */
  issuer: string;
  /** Python default: `""`. */
  subject: string;
  /** Python default: `{}`. */
  checks: Record<string, boolean>;
  /** Python default: `[]`. */
  errors: string[];
  /** Python default: `[]`. */
  warnings: string[];
  /** Resolver-returned object. Python default: `None`. */
  mandate?: Mandate | null;
  /** Short summary of highest-level failure. Python default: `None`. */
  failureReason?: string | null;
  /** ISO 8601 revocation timestamp. Python default: `None`. */
  revokedAt?: string | null;
  /** Trust tier the verifier ran. Python default: `None`. */
  tier?: string | null;
}

/**
 * Construct a {@link MandateVerificationResult} with the Python dataclass
 * defaults (`mandate_id=""`, `issuer=""`, `subject=""`, `checks={}`,
 * `errors=[]`, `warnings=[]`, optional resolver fields `None`). `valid` is
 * required (Python's only non-default field).
 */
export function makeMandateVerificationResult(
  fields: { valid: boolean } & Partial<MandateVerificationResult>,
): MandateVerificationResult {
  return {
    mandateId: '',
    issuer: '',
    subject: '',
    checks: {},
    errors: [],
    warnings: [],
    mandate: null,
    failureReason: null,
    revokedAt: null,
    tier: null,
    ...fields,
  };
}

/**
 * Serialize a {@link MandateVerificationResult} to its wire form.
 *
 * Parity with Python `MandateVerificationResult.to_dict()`: emits the seven
 * always-present keys first (`valid`, `mandate_id`, `issuer`, `subject`,
 * `checks`, `errors`, `warnings`), then appends each optional key IN ORDER
 * (`failure_reason`, `revoked_at`, `tier`, `mandate`) ONLY when it is non-null
 * (Python `if self.x is not None`). When present, `mandate` is serialized via
 * {@link mandateToDict}, matching Python's `self.mandate.to_dict()`.
 */
export function mandateVerificationResultToDict(
  result: MandateVerificationResult,
): Record<string, unknown> {
  const d: Record<string, unknown> = {
    valid: result.valid,
    mandate_id: result.mandateId,
    issuer: result.issuer,
    subject: result.subject,
    checks: result.checks,
    errors: result.errors,
    warnings: result.warnings,
  };
  if (result.failureReason !== undefined && result.failureReason !== null) {
    d.failure_reason = result.failureReason;
  }
  if (result.revokedAt !== undefined && result.revokedAt !== null) {
    d.revoked_at = result.revokedAt;
  }
  if (result.tier !== undefined && result.tier !== null) {
    d.tier = result.tier;
  }
  if (result.mandate !== undefined && result.mandate !== null) {
    d.mandate = mandateToDict(result.mandate);
  }
  return d;
}

// ---------------------------------------------------------------------------
// Static schema + constraint-pattern constants
// ---------------------------------------------------------------------------

/** Error raised for invalid mandate-model input (mirrors Python `KeyError` / `ValueError`). */
export class MandateValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MandateValidationError';
  }
}

/**
 * JSON Schema for mandate validation. Mirrors Python `MANDATE_JSON_SCHEMA`
 * byte-for-byte (the deferred engine feeds this to a jsonschema validator).
 * Exported as a frozen constant; the parity test canonicalizes both this and
 * the Python copy and asserts identical bytes.
 */
export const MANDATE_JSON_SCHEMA: Record<string, unknown> = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'urn:concordia:schema:mandate:v1',
  title: 'Concordia Mandate Credential',
  description:
    'A signed credential authorizing an agent to act within constraints.',
  type: 'object',
  required: [
    'mandate_id',
    'issuer',
    'subject',
    'issued_at',
    'validity',
    'constraints',
    'algorithm',
  ],
  properties: {
    mandate_id: {
      type: 'string',
      pattern: '^urn:concordia:mandate:',
      description: 'Unique mandate identifier in URN format',
    },
    issuer: {
      type: 'string',
      minLength: 1,
      description: 'DID or agent_id of the mandate issuer',
    },
    subject: {
      type: 'string',
      minLength: 1,
      description: 'DID or agent_id of the authorized agent',
    },
    issued_at: {
      type: 'string',
      format: 'date-time',
      description: 'ISO 8601 issuance timestamp',
    },
    algorithm: {
      type: 'string',
      enum: ['EdDSA', 'ES256'],
      description: 'Signing algorithm',
    },
    status: {
      type: 'string',
      enum: ['active', 'expired', 'revoked', 'suspended'],
      default: 'active',
    },
    validity: {
      type: 'object',
      required: ['mode'],
      properties: {
        mode: {
          type: 'string',
          enum: ['sequence', 'windowed', 'state_bound'],
        },
        not_before: { type: 'string', format: 'date-time' },
        not_after: { type: 'string', format: 'date-time' },
        sequence_key: { type: 'string' },
        state_condition: { type: 'string' },
        max_uses: { type: 'integer', minimum: 1 },
      },
      allOf: [
        {
          if: { properties: { mode: { const: 'windowed' } } },
          then: { required: ['not_before', 'not_after'] },
        },
        {
          if: { properties: { mode: { const: 'sequence' } } },
          then: { required: ['sequence_key'] },
        },
        {
          if: { properties: { mode: { const: 'state_bound' } } },
          then: { required: ['state_condition'] },
        },
      ],
    },
    constraints: {
      type: 'object',
      description: 'JSON Schema defining what the mandate authorizes',
      minProperties: 1,
    },
    delegation_chain: {
      type: 'array',
      items: {
        type: 'object',
        required: [
          'delegator',
          'delegate',
          'delegated_at',
          'signature',
          'algorithm',
        ],
        properties: {
          delegator: { type: 'string', minLength: 1 },
          delegate: { type: 'string', minLength: 1 },
          delegated_at: { type: 'string', format: 'date-time' },
          signature: { type: 'string', minLength: 1 },
          algorithm: { type: 'string', enum: ['EdDSA', 'ES256'] },
          scope_restriction: { type: 'object' },
        },
      },
    },
    revocation_endpoint: {
      type: 'string',
      format: 'uri',
    },
    revoked_at: {
      type: 'string',
      format: 'date-time',
      description: 'ISO 8601 revocation timestamp surfaced by a resolver',
    },
    metadata: {
      type: 'object',
    },
    signature: {
      type: 'string',
      description: 'Base64url signature over all fields except signature',
    },
  },
  additionalProperties: false,
};

/**
 * Common JSON-Schema constraint patterns a mandate's `constraints` can reuse.
 * Mirrors Python `CONSTRAINT_PATTERNS` byte-for-byte.
 */
export const CONSTRAINT_PATTERNS: Record<string, Record<string, unknown>> = {
  max_spend: {
    type: 'object',
    properties: {
      amount: { type: 'number', minimum: 0 },
      currency: { type: 'string', minLength: 3, maxLength: 3 },
    },
    required: ['amount', 'currency'],
  },
  allowed_categories: {
    type: 'object',
    properties: {
      categories: {
        type: 'array',
        items: { type: 'string' },
        minItems: 1,
      },
    },
    required: ['categories'],
  },
  geographic_bounds: {
    type: 'object',
    properties: {
      allowed_regions: {
        type: 'array',
        items: { type: 'string' },
      },
      excluded_regions: {
        type: 'array',
        items: { type: 'string' },
      },
    },
  },
  temporal_budget: {
    type: 'object',
    properties: {
      max_sessions: { type: 'integer', minimum: 1 },
      max_concurrent: { type: 'integer', minimum: 1 },
    },
  },
};
