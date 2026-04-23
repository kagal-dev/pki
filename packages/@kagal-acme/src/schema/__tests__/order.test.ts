// Order schema tests (RFC 8555 §7.1.3)

import { describe, expect, it } from 'vitest';

import { validateOrder } from '..';

const minimalOrder = {
  status: 'pending',
  identifiers: [
    { type: 'dns', value: 'example.com' },
  ],
  authorizations: [
    'https://ca.example/authz/1',
  ],
  finalize: 'https://ca.example/order/1/finalize',
};

describe('validateOrder', () => {
  it('accepts a minimal pending order', () => {
    const result = validateOrder(minimalOrder);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status).toBe('pending');
      expect(result.data.identifiers).toHaveLength(1);
    }
  });

  it('accepts all order statuses', () => {
    for (const status of [
      'pending', 'ready', 'processing',
      'valid', 'invalid',
    ]) {
      const result = validateOrder({
        ...minimalOrder, status,
      });
      expect(result.success).toBe(true);
    }
  });

  it('accepts a full order with optional fields', () => {
    const result = validateOrder({
      ...minimalOrder,
      status: 'valid',
      expires: '2026-04-28T00:00:00Z',
      notBefore: '2026-03-28T00:00:00Z',
      notAfter: '2026-06-28T00:00:00Z',
      certificate: 'https://ca.example/cert/1',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.certificate)
        .toBe('https://ca.example/cert/1');
    }
  });

  it('accepts with error', () => {
    const result = validateOrder({
      ...minimalOrder,
      status: 'invalid',
      error: {
        type: 'urn:ietf:params:acme:error:rejectedIdentifier',
        detail: 'Rejected',
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts with ARI replaces (RFC 9773)', () => {
    const result = validateOrder({
      ...minimalOrder,
      replaces: 'aYhba4dGQEHBKIMhAbKqAw.AAABfnE',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.replaces)
        .toBe('aYhba4dGQEHBKIMhAbKqAw.AAABfnE');
    }
  });

  it('accepts with profile (Profiles extension)', () => {
    const result = validateOrder({
      ...minimalOrder,
      profile: 'tlsserver',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.profile).toBe('tlsserver');
    }
  });

  it('rejects unknown status', () => {
    const result = validateOrder({
      ...minimalOrder,
      status: 'expired',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing identifiers', () => {
    const result = validateOrder({
      status: 'pending',
      authorizations: ['https://ca.example/authz/1'],
      finalize: 'https://ca.example/order/1/finalize',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing finalize', () => {
    const result = validateOrder({
      status: 'pending',
      identifiers: [
        { type: 'dns', value: 'example.com' },
      ],
      authorizations: ['https://ca.example/authz/1'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-URL finalize', () => {
    const result = validateOrder({
      ...minimalOrder,
      finalize: 'not a url',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-URL authorization entry', () => {
    const result = validateOrder({
      ...minimalOrder,
      authorizations: ['not a url'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-URL certificate', () => {
    const result = validateOrder({
      ...minimalOrder,
      status: 'valid',
      certificate: 'not a url',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-timestamp expires', () => {
    const result = validateOrder({
      ...minimalOrder,
      expires: 'yesterday',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-timestamp notBefore', () => {
    const result = validateOrder({
      ...minimalOrder,
      notBefore: '2026/03/28',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-timestamp notAfter', () => {
    const result = validateOrder({
      ...minimalOrder,
      notAfter: 'soon',
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateOrder({
      ...minimalOrder,
      retry: { after: 30 },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as Record<string, unknown>).retry,
      ).toEqual({ after: 30 });
    }
  });
});
