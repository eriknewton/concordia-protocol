// Must match `REFERENCE_ATTESTATION_VALIDITY_SECONDS` in
// concordia/attestation.py. The draft cap is elapsed seconds, not a calendar
// quantity, and role aliases derive from this one value.
export const REFERENCE_ATTESTATION_VALIDITY_SECONDS = 90 * 24 * 60 * 60;

export const DEFAULT_ATTESTATION_VALIDITY_SECONDS = REFERENCE_ATTESTATION_VALIDITY_SECONDS;
export const MAX_ATTESTATION_VALIDITY_SECONDS = DEFAULT_ATTESTATION_VALIDITY_SECONDS;
export const MAX_RELYING_VALIDITY_LIFETIME_SECONDS = REFERENCE_ATTESTATION_VALIDITY_SECONDS;

export type VersionTuple = readonly [bigint, bigint, bigint];

export type StrictVersionParseResult =
  { ok: true; version: VersionTuple } | { ok: false; reason: 'grammar' | 'component_too_long' };

export const SET_BINDING_MIN: VersionTuple = [0n, 3n, 0n];
export const LEGACY_FLOOR_VERSION: VersionTuple = [0n, 5n, 0n];
export const IMPLEMENTED_ATTESTATION_VERSION: VersionTuple = [0n, 6n, 0n];

// Must match `_SEMVER_RE` in concordia/attestation.py: ASCII digits, no leading
// zeros and no trailing newline. The version grammar is a structure gate, not a
// coercion site.
export const STRICT_VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;

// Equals CPython's default int_max_str_digits, chosen so default-settings
// behavior is unchanged. Must match
// MAX_ATTESTATION_VERSION_COMPONENT_DIGITS in concordia/attestation.py.
export const MAX_ATTESTATION_VERSION_COMPONENT_DIGITS = 4300;

export const VERSION_COMPONENT_TOO_LONG_ERROR = 'concordia_attestation component is too long';

export function parseStrictVersion(version: unknown): StrictVersionParseResult {
  if (typeof version !== 'string' || !STRICT_VERSION_PATTERN.test(version)) {
    return { ok: false, reason: 'grammar' };
  }
  const parts = version.split('.');
  if (
    parts.length !== 3 ||
    parts.some((part) => part.length > MAX_ATTESTATION_VERSION_COMPONENT_DIGITS)
  ) {
    return { ok: false, reason: 'component_too_long' };
  }
  try {
    return {
      ok: true,
      version: [BigInt(parts[0]!), BigInt(parts[1]!), BigInt(parts[2]!)],
    };
  } catch {
    return { ok: false, reason: 'component_too_long' };
  }
}

export function compareVersion(a: VersionTuple, b: VersionTuple): number {
  for (let index = 0; index < 3; index += 1) {
    if (a[index]! < b[index]!) return -1;
    if (a[index]! > b[index]!) return 1;
  }
  return 0;
}
