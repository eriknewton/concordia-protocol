export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalizationError';
  }
}

export function checkNoSpecialFloats(value: unknown): void {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError(
        `Cannot serialize non-finite number: ${value}`,
      );
    }
    if (Object.is(value, -0)) {
      throw new CanonicalizationError('Cannot serialize negative zero (-0)');
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) checkNoSpecialFloats(item);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value)) checkNoSpecialFloats(v);
  }
}
