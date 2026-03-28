// Challenge schema tests (RFC 8555 §8)

import { describe, expect, it } from 'vitest';

import { validateChallenge } from '..';

describe('validateChallenge', () => {
  it('accepts an http-01 challenge', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/1',
      status: 'pending',
      token: 'abc123',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.type).toBe('http-01');
    }
  });

  it('accepts a dns-01 challenge', () => {
    const result = validateChallenge({
      type: 'dns-01',
      url: 'https://ca.example/chall/2',
      status: 'valid',
      token: 'def456',
      validated: '2026-03-28T12:00:00Z',
    });
    expect(result.success).toBe(true);
  });

  it('accepts a tls-alpn-01 challenge', () => {
    const result = validateChallenge({
      type: 'tls-alpn-01',
      url: 'https://ca.example/chall/3',
      status: 'processing',
      token: 'ghi789',
    });
    expect(result.success).toBe(true);
  });

  it('accepts a challenge with error', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/4',
      status: 'invalid',
      token: 'xyz',
      error: {
        type: 'urn:ietf:params:acme:error:connection',
        detail: 'Connection refused',
        status: 400,
      },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status).toBe('invalid');
    }
  });

  it('rejects unknown challenge type', () => {
    const result = validateChallenge({
      type: 'email-reply-00',
      url: 'https://ca.example/chall/5',
      status: 'pending',
      token: 'abc',
    });
    expect(result.success).toBe(false);
  });

  it('rejects invalid status', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/6',
      status: 'ready',
      token: 'abc',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing token', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/7',
      status: 'pending',
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/8',
      status: 'pending',
      token: 'abc',
      futureField: 42,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as Record<string, unknown>)
          .futureField,
      ).toBe(42);
    }
  });
});
