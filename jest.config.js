/** @format */
/* eslint @typescript-eslint/no-var-requires:0 */

// const { pathsToModuleNameMapper } = require('ts-jest/utils');
const { jsWithTs: tsjPreset } = require('ts-jest/presets');
// In the following statement, replace `./tsconfig` with the path to your `tsconfig` file
// which contains the path mapping (ie the `compilerOptions.paths` option):
// const { compilerOptions } = require('./tsconfig');
// const localPathMapper = pathsToModuleNameMapper(compilerOptions.paths, { prefix: '<rootDir>/' });

module.exports = {
  testTimeout: 180000,
  verbose: true,
  preset: 'ts-jest',
  testEnvironment: 'node',
  setupFiles: ['./jest.setup.ts'],
  globals: {
    'ts-jest': {
      tsconfig: 'tsconfig.jest.json',
      // Disable type-checking
      isolatedModules: true,
    },
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],
  moduleNameMapper: {
    // ...localPathMapper,
    // eslint-disable-next-line max-len
    '\\.(jpg|ico|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga|css|scss|sass|less)(\\?.*)?$':
      '<rootDir>/__mocks__/fileMock.js',
  },
  transform: {
    ...tsjPreset.transform,
    '.+\\.(css|styl|less|sass|scss|png|jpg|ttf|woff|woff2)(\\?.*)?$': 'jest-transform-stub',
    '^.+\\.svg$': 'jest-svg-transformer',
  },
  // transformIgnorePatterns: ['node_modules/(?!(simple-git/src))/'],
  testMatch: ['**/__tests__/**/*.[jt]s?(x)', '**/(*.)+(spec|test).[jt]s?(x)'],
  testPathIgnorePatterns: ['<rootDir>/.git/', '<rootDir>/dist/', '<rootDir>/node_modules/', '<rootDir>/.local/'],
};
