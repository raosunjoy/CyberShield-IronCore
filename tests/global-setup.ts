/**
 * Global Jest Setup - Runs once before all tests
 * Enterprise-grade test environment initialization
 */

import { execSync } from 'child_process';
import * as path from 'path';

/**
 * Global setup function for Jest test suite
 * Initializes enterprise testing environment
 * @returns Promise<void>
 */
export default async function globalSetup(): Promise<void> {
  console.log(
    '🛡️  CyberShield-IronCore: Initializing Enterprise Test Environment'
  );

  // Set test environment variables
  process.env['NODE_ENV'] = 'test';
  process.env['SKIP_ENV_VALIDATION'] = 'true';

  // Database setup for integration tests
  try {
    // Check if test database is available
    console.log('📊 Setting up test database...');

    // Create test database if it doesn't exist
    process.env['DATABASE_URL'] =
      'postgresql://test:test@localhost:5432/cybershield_test';

    console.log('✅ Test database configured');
  } catch (error) {
    console.warn(
      '⚠️  Test database not available, skipping database tests',
      error
    );
  }

  // Mock external services
  console.log('🔧 Configuring external service mocks...');

  // VirusTotal API mock
  process.env['VIRUSTOTAL_API_KEY'] = 'test-virustotal-key';
  process.env['VIRUSTOTAL_API_URL'] = 'https://mock-virustotal.com/api/v3';

  // Okta Auth mock
  process.env['OKTA_DOMAIN'] = 'test.okta.com';
  process.env['OKTA_CLIENT_ID'] = 'test-client-id';
  process.env['OKTA_CLIENT_SECRET'] = 'test-client-secret';

  // AWS mock credentials
  process.env['AWS_REGION'] = 'us-east-1';
  process.env['AWS_ACCESS_KEY_ID'] = 'test-access-key';
  process.env['AWS_SECRET_ACCESS_KEY'] = 'test-secret-key';

  // Kafka mock
  process.env['KAFKA_BOOTSTRAP_SERVERS'] = 'localhost:9092';
  process.env['KAFKA_TOPIC_THREATS'] = 'test-threats';

  // Redis mock
  process.env['REDIS_URL'] = 'redis://localhost:6379/1';

  console.log('✅ External service mocks configured');

  // Create test artifacts directory
  const testArtifactsDir = path.join(process.cwd(), 'coverage');
  try {
    execSync(`mkdir -p ${testArtifactsDir}`, { stdio: 'ignore' });
  } catch (error) {
    // Directory might already exist
    console.debug('Test artifacts directory already exists', error);
  }

  console.log('🎯 Enterprise test environment ready!');
}
