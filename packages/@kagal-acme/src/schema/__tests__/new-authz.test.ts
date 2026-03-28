// NewAuthz schema tests (RFC 8555 §7.4.1)

import { describe, expect, it } from 'vitest';

import {
  validateDeactivateAuthorization,
  validateNewAuthz,
} from '..';

describe('validateNewAuthz', () => {
  it('accepts DNS identifier', () => {
    const result = validateNewAuthz({
      identifier: {
        type: 'dns' as const,
        value: 'example.com',
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts IP identifier', () => {
    const result = validateNewAuthz({
      identifier: {
        type: 'ip' as const,
        value: '192.0.2.1',
      },
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing identifier', () => {
    const result = validateNewAuthz({});
    expect(result.success).toBe(false);
  });

  it('rejects unknown fields (strict)', () => {
    const result = validateNewAuthz({
      identifier: {
        type: 'dns' as const,
        value: 'example.com',
      },
      extra: true,
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown identifier fields (strict)', () => {
    const result = validateNewAuthz({
      identifier: {
        type: 'dns' as const,
        value: 'example.com',
        extra: true,
      },
    });
    expect(result.success).toBe(false);
  });
});

describe('validateDeactivateAuthorization', () => {
  it('accepts deactivation', () => {
    const result =
      validateDeactivateAuthorization({
        status: 'deactivated',
      });
    expect(result.success).toBe(true);
  });

  it('rejects other status', () => {
    const result =
      validateDeactivateAuthorization({
        status: 'valid',
      });
    expect(result.success).toBe(false);
  });

  it('rejects unknown fields (strict)', () => {
    const result =
      validateDeactivateAuthorization({
        status: 'deactivated',
        extra: true,
      });
    expect(result.success).toBe(false);
  });
});
