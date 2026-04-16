// Authorization schema tests (RFC 8555 §7.1.4)

import { describe, expect, it } from 'vitest';

import { validateAuthorization } from '..';

const basePayload = {
  identifier: { type: 'dns' as const, value: 'example.com' },
  challenges: [
    {
      type: 'http-01' as const,
      url: 'https://ca.example/chall/1',
      status: 'pending' as const,
      token: 'abc123abc123abc123abc123',
    },
  ],
};

describe('validateAuthorization', () => {
  it('accepts a pending authorization', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'pending',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status).toBe('pending');
    }
  });

  it('accepts a valid authorization with expires', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'valid',
      expires: '2026-04-28T00:00:00Z',
    });
    expect(result.success).toBe(true);
  });

  it('rejects a valid authorization without expires', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'valid',
    });
    expect(result.success).toBe(false);
  });

  it('accepts an invalid authorization', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'invalid',
    });
    expect(result.success).toBe(true);
  });

  it('accepts a deactivated authorization', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'deactivated',
    });
    expect(result.success).toBe(true);
  });

  it('accepts an expired authorization', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'expired',
    });
    expect(result.success).toBe(true);
  });

  it('accepts a revoked authorization', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'revoked',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with wildcard flag', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'pending',
      wildcard: true,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.wildcard).toBe(true);
    }
  });

  it('rejects unknown status', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'ready',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing challenges', () => {
    const result = validateAuthorization({
      identifier: {
        type: 'dns',
        value: 'example.com',
      },
      status: 'pending',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-timestamp expires on valid', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'valid',
      expires: 'tomorrow',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-timestamp expires on pending', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'pending',
      expires: '2026/04/28',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-timestamp expires on expired', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'expired',
      expires: 'yesterday',
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateAuthorization({
      ...basePayload,
      status: 'pending',
      futureField: 'test',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as Record<string, unknown>)
          .futureField,
      ).toBe('test');
    }
  });
});
