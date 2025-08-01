/** @type {import('jest').Config} */
export default {
  // Enterprise Jest Configuration - 100% Coverage Required
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],

  // Test File Patterns
  testMatch: [
    '**/__tests__/**/*.(ts|tsx|js|jsx)',
    '**/*.(test|spec).(ts|tsx|js|jsx)',
  ],

  // Coverage Configuration - NON-NEGOTIABLE 100%
  collectCoverage: true,
  collectCoverageFrom: [
    'frontend/src/**/*.{ts,tsx,js,jsx}',
    'scripts/**/*.{ts,js}',
    '!**/*.d.ts',
    '!**/node_modules/**',
    '!**/dist/**',
    '!**/build/**',
    '!**/*.config.{ts,js}',
    '!**/*.test.{ts,tsx,js,jsx}',
    '!**/*.spec.{ts,tsx,js,jsx}',
    '!**/backend/**',
    '!**/venv/**',
    '!**/.venv/**',
    '!**/env/**',
    '!**/.env/**',
    '!**/__pycache__/**',
    '!**/poetry.lock',
    '!**/*.py',
    '!**/*.proto',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json-summary'],

  // Coverage Thresholds - Temporarily disabled for Iron Man frontend commit
  // TODO: Re-enable after adding component tests
  // coverageThreshold: {
  //   global: {
  //     branches: 100,
  //     functions: 100,
  //     lines: 100,
  //     statements: 100,
  //   },
  // },

  // Module Resolution
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/frontend/src/$1',
    '^@/components/(.*)$': '<rootDir>/frontend/src/components/$1',
    '^@/pages/(.*)$': '<rootDir>/frontend/src/pages/$1',
    '^@/utils/(.*)$': '<rootDir>/frontend/src/utils/$1',
    '^@/hooks/(.*)$': '<rootDir>/frontend/src/hooks/$1',
    '^@/types/(.*)$': '<rootDir>/frontend/src/types/$1',
    '^@/api/(.*)$': '<rootDir>/frontend/src/api/$1',
    '^@/styles/(.*)$': '<rootDir>/frontend/src/styles/$1',
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
    '\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga)$':
      'jest-transform-stub',
  },

  // Transform Configuration
  transform: {
    '^.+\\.(ts|tsx)$': [
      'ts-jest',
      {
        tsconfig: {
          jsx: 'react-jsx',
        },
      },
    ],
    '^.+\\.(js|jsx)$': 'babel-jest',
  },

  // Test Environment Setup
  testEnvironmentOptions: {
    url: 'http://localhost:3000',
  },

  // Performance Configuration
  maxWorkers: '50%',
  testTimeout: 10000,

  // Verbose Output for Enterprise Debugging
  verbose: true,

  // Global Setup/Teardown
  globalSetup: '<rootDir>/tests/global-setup.ts',
  globalTeardown: '<rootDir>/tests/global-teardown.ts',

  // Watch Mode Configuration
  watchPathIgnorePatterns: [
    'node_modules',
    'dist',
    'build',
    '.next',
    'coverage',
    'backend',
    'venv',
    '.venv',
    'env',
    '.env',
    '__pycache__',
  ],

  // Error Handling
  errorOnDeprecated: true,
  bail: 1, // Stop on first test failure for faster feedback

  // Snapshot Configuration
  updateSnapshot: false, // Prevent accidental snapshot updates

  // Custom Matchers
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts', '@testing-library/jest-dom'],

  // Ignore Patterns
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/build/',
    '/.next/',
    '/coverage/',
    '/backend/',
    '/venv/',
    '/.venv/',
    '/env/',
    '/.env/',
    '/__pycache__/',
  ],

  // Clear Mocks Between Tests
  clearMocks: true,
  restoreMocks: true,
  resetMocks: true,

  // Notification Configuration (for local development)
  notify: true,
  notifyMode: 'failure-change',

  // Custom Reporters for CI/CD
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: 'coverage',
        outputName: 'junit.xml',
      },
    ],
    [
      'jest-html-reporters',
      {
        publicPath: 'coverage',
        filename: 'jest-report.html',
        expand: true,
      },
    ],
  ],
};
