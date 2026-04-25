// NewOrder schema tests (RFC 8555 §7.4)

import { describe, expect, it } from 'vitest';

import { validateNewOrder } from '..';

const minimalOrder = {
  identifiers: [
    {
      type: 'dns' as const,
      value: 'example.com',
    },
  ],
};

describe('validateNewOrder', () => {
  it('accepts minimal order', () => {
    const result = validateNewOrder(minimalOrder);
    expect(result.success).toBe(true);
  });

  it('accepts with notBefore/notAfter', () => {
    const result = validateNewOrder({
      ...minimalOrder,
      notBefore: '2026-01-01T00:00:00Z',
      notAfter: '2026-12-31T23:59:59Z',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with profile', () => {
    const result = validateNewOrder({
      ...minimalOrder,
      profile: 'tls-server',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with ARI replaces', () => {
    const result = validateNewOrder({
      ...minimalOrder,
      replaces:
        'aYhba4dGQEHBKIMhAbKqAw.AAABfnE',
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing identifiers', () => {
    const result = validateNewOrder({});
    expect(result.success).toBe(false);
  });

  it('rejects empty identifiers', () => {
    const result = validateNewOrder({
      identifiers: [],
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown fields (strict)', () => {
    const result = validateNewOrder({
      ...minimalOrder,
      extra: true,
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown identifier fields (strict)', () => {
    const result = validateNewOrder({
      identifiers: [
        {
          type: 'dns' as const,
          value: 'example.com',
          extra: true,
        },
      ],
    });
    expect(result.success).toBe(false);
  });
});
