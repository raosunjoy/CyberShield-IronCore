/**
 * Test utility functions for CyberShield-IronCore
 * Enterprise-grade testing helpers
 */

/**
 * Simple test function to verify our quality gates
 * @param message - The message to return
 * @returns The formatted message
 */
export function formatMessage(message: string): string {
  if (!message) {
    throw new Error('Message is required');
  }
  return `🛡️ CyberShield: ${message}`;
}

/**
 * Enterprise math utility for testing
 * @param a - First number
 * @param b - Second number  
 * @returns Sum of the numbers
 */
export function add(a: number, b: number): number {
  return a + b;
}