// Flat ESLint config for the Concordia JS SDK.
//
// Lint-only adoption: typescript-eslint's non-type-checked `recommended` set
// (real-bug rules: no-unused-vars, no-explicit-any guards off where the SDK
// legitimately bridges untyped JSON, etc.). Formatting is owned by Prettier;
// `eslint-config-prettier` (applied last) disables every stylistic rule that
// would fight the formatter, so `npm run lint` and `npm run format` never
// disagree.
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'tests/fixtures/**'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // The SDK intentionally crosses into untyped JSON at the protocol
      // boundary (canonicalization, schema validation, Python parity). Flag
      // unused vars as errors but allow a leading-underscore opt-out for
      // deliberately-unused signature params.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  {
    // Tests assert against dynamically-shaped parity vectors and exercise error
    // paths, so `any` and non-null assertions are expected here.
    files: ['tests/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
  prettier,
);
