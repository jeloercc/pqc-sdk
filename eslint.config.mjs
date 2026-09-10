import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/coverage/**',
      '**/node_modules/**',
      '.turbo/**',
      // Third-party source copied verbatim from @noble/post-quantum. Linting it to this
      // repo's rules would mean reformatting upstream code, which destroys the property
      // that makes vendoring reviewable: a small, readable diff against the original.
      // Local modifications are marked inline and tested separately. See
      // packages/core/src/vendor/ml-kem/NOTICE.md.
      // Only the copied files; tests written by this repo under __tests__/ stay linted.
      'packages/core/src/vendor/ml-kem/ml-kem.ts',
      'packages/core/src/vendor/ml-kem/_crystals.ts',
      'packages/core/src/vendor/ml-kem/utils.ts',
      'packages/core/src/vendor/ml-dsa/ml-dsa.ts',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ['**/*.{js,mjs,cjs}'],
    ...tseslint.configs.disableTypeChecked,
  },
  prettier,
);
