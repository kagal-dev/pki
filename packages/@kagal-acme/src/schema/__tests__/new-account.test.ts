// NewAccount schema tests (RFC 8555 §7.3)

import { describe, expect, it } from 'vitest';

import {
  validateDeactivateAccount,
  validateNewAccount,
} from '..';

describe('validateNewAccount', () => {
  it('accepts empty payload', () => {
    const result = validateNewAccount({});
    expect(result.success).toBe(true);
  });

  it('accepts with contact', () => {
    const result = validateNewAccount({
      contact: [
        'mailto:cert-admin@example.org',
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts with termsOfServiceAgreed', () => {
    const result = validateNewAccount({
      termsOfServiceAgreed: true,
    });
    expect(result.success).toBe(true);
  });

  it('accepts with onlyReturnExisting', () => {
    const result = validateNewAccount({
      onlyReturnExisting: true,
    });
    expect(result.success).toBe(true);
  });

  it('accepts with EAB', () => {
    const result = validateNewAccount({
      externalAccountBinding: {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        payload: 'eyJ0ZXN0IjoxfQ',
        signature: 'abc123',
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts with all fields', () => {
    const result = validateNewAccount({
      contact: ['mailto:admin@example.org'],
      termsOfServiceAgreed: true,
      onlyReturnExisting: false,
      externalAccountBinding: {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        payload: 'eyJ0ZXN0IjoxfQ',
        signature: 'abc123',
      },
    });
    expect(result.success).toBe(true);
  });

  it('rejects unknown fields (strict)', () => {
    const result = validateNewAccount({
      extra: true,
    });
    expect(result.success).toBe(false);
  });
});

describe('validateDeactivateAccount', () => {
  it('accepts deactivation', () => {
    const result = validateDeactivateAccount({
      status: 'deactivated',
    });
    expect(result.success).toBe(true);
  });

  it('rejects other status', () => {
    const result = validateDeactivateAccount({
      status: 'valid',
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown fields (strict)', () => {
    const result = validateDeactivateAccount({
      status: 'deactivated',
      extra: true,
    });
    expect(result.success).toBe(false);
  });
});
