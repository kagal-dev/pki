// Challenge schema tests (RFC 8555 §8)

import { describe, expect, it } from 'vitest';

import { validateChallenge } from '..';

describe('validateChallenge', () => {
  it('accepts an http-01 challenge', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/1',
      status: 'pending',
      token: 'abc123abc123abc123abc123',
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
      token: 'def456def456def456def456',
      validated: '2026-03-28T12:00:00Z',
    });
    expect(result.success).toBe(true);
  });

  it('accepts a tls-alpn-01 challenge', () => {
    const result = validateChallenge({
      type: 'tls-alpn-01',
      url: 'https://ca.example/chall/3',
      status: 'processing',
      token: 'ghi789ghi789ghi789ghi789',
    });
    expect(result.success).toBe(true);
  });

  it('accepts a challenge with error', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/4',
      status: 'invalid',
      token: 'xyz789xyz789xyz789xyz789',
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
      token: 'abc123abc123abc123abc123',
    });
    expect(result.success).toBe(false);
  });

  it('rejects invalid status', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/6',
      status: 'ready',
      token: 'abc123abc123abc123abc123',
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

  it('rejects non-URL challenge url', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'not a url',
      status: 'pending',
      token: 'abc123abc123abc123abc123',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-timestamp validated', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/1',
      status: 'valid',
      token: 'abc123abc123abc123abc123',
      validated: 'yesterday',
    });
    expect(result.success).toBe(false);
  });

  it('accepts a 25-character alphabet-only token', () => {
    // §8 — token is "constructed only from characters
    // in the base64url alphabet" with ≥128 bits of
    // entropy. 25 alphabet-only chars is conformant
    // even though `25 % 4 === 1` would fail a base64
    // decode-framing check.
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/1',
      status: 'pending',
      token: 'A'.repeat(25),
    });
    expect(result.success).toBe(true);
  });

  it('rejects token shorter than 128 bits of entropy', () => {
    // §8.1 — token MUST carry ≥ 128 bits of entropy.
    // Base64url-encoded, that's 22 characters.
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/1',
      status: 'pending',
      token: 'abc123abc123abc', // 15 chars — valid format, too short.
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64url token', () => {
    // §8.1 — token MUST be base64url. Use a 25-char
    // token so only the alphabet regex trips, not
    // the minLength floor.
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/1',
      status: 'pending',
      token: 'abc123abc123 abc123abc123',
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty token', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/1',
      status: 'pending',
      token: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects token with standard-base64 `+`', () => {
    // Use a 25-char token so only the alphabet
    // regex trips, not the minLength floor.
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/1',
      status: 'pending',
      token: 'abc123abc123+abc123abc123',
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateChallenge({
      type: 'http-01',
      url: 'https://ca.example/chall/8',
      status: 'pending',
      token: 'abc123abc123abc123abc123',
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
