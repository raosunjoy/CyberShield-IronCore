/**
 * Test suite for test utilities
 * Demonstrates 100% test coverage requirement
 */

import { describe, it, expect } from '@jest/globals';
import { formatMessage, add } from './test-utils';

describe('Test Utils', () => {
  describe('formatMessage', () => {
    it('should format message correctly', () => {
      const result = formatMessage('Hello World');
      expect(result).toBe('🛡️ CyberShield: Hello World');
    });

    it('should throw error for empty message', () => {
      expect(() => formatMessage('')).toThrow('Message is required');
    });

    it('should handle special characters', () => {
      const result = formatMessage('Test with 🔥 emoji');
      expect(result).toBe('🛡️ CyberShield: Test with 🔥 emoji');
    });
  });

  describe('add', () => {
    it('should add two positive numbers', () => {
      expect(add(2, 3)).toBe(5);
    });

    it('should add negative numbers', () => {
      expect(add(-2, -3)).toBe(-5);
    });

    it('should add zero', () => {
      expect(add(5, 0)).toBe(5);
    });

    it('should handle decimal numbers', () => {
      expect(add(1.5, 2.5)).toBe(4);
    });
  });
});
