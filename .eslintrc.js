module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    sourceType: 'module',
    jsx: true,
    useJSXTextNode: true,
    ecmaVersion: 2020,
    ecmaFeatures: {
      jsx: true,
    },
    // project: ['./tsconfig.json', 'apps/*/tsconfig.json', 'libs/*/tsconfig.json'],
  },
  plugins: [
    '@typescript-eslint',
  ],
  extends: [
    'plugin:@typescript-eslint/eslint-recommended',
    'plugin:@typescript-eslint/recommended',
    'prettier',
    'prettier/@typescript-eslint',
  ],
  settings: {
    typescript: {
      // alwaysTryTypes: true,
      project: ['tsconfig.json'],
    },
    node: {
      extensions: ['.ts', '.tsx', '.js', '.jsx'],
    },
  },
  root: true,
  env: {
    node: true,
  },
  rules: {
    '@typescript-eslint/interface-name-prefix': 'off',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-explicit-any': 'off',
  },
};
