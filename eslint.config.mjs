// eslint.config.mjs
import { js } from '@eslint/js';
import ts from '@typescript-eslint/eslint-plugin';
import prettier from 'eslint-plugin-prettier';
import globals from 'globals';

export default [
  {
    ignores: ['dist/**', 'node_modules/**'],
  },
  js.configs.recommended, // ESLint recommended rules
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
      parser: '@typescript-eslint/parser',
      parserOptions: {
        project: './tsconfig.json',
      },
    },
  },
  {
    plugins: {
      '@typescript-eslint': ts,
      prettier,
    },
    rules: {
      'prettier/prettier': ['error'],
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-floating-promises': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
    },
  },
];
