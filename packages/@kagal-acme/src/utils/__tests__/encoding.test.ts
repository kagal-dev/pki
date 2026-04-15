// base64url + random helpers (RFC 7515 §2)

import { describe, expect, it } from 'vitest';

import { decodeBase64url, encodeBase64url, getRandom } from '..';

const bytes = (...xs: number[]) => new Uint8Array(xs);

describe('encodeBase64url', () => {
  it('encodes without padding', async () => {
    // "Hello" → SGVsbG8 (5 bytes, no padding)
    expect(encodeBase64url(bytes(0x48, 0x65, 0x6C, 0x6C, 0x6F)))
      .toBe('SGVsbG8');
  });

  it('uses URL-safe alphabet (- and _)', async () => {
    // Bytes chosen to produce `+` and `/` in standard
    // base64 (0xFB, 0xFF → `+/8=`); base64url must emit
    // `-_8` instead.
    expect(encodeBase64url(bytes(0xFB, 0xFF)))
      .toBe('-_8');
  });

  it('emits empty string for empty input', async () => {
    expect(encodeBase64url(bytes())).toBe('');
  });
});

describe('decodeBase64url', () => {
  it('round-trips encodeBase64url', async () => {
    const original = crypto.getRandomValues(new Uint8Array(32));
    const encoded = encodeBase64url(original);
    const decoded = new Uint8Array(decodeBase64url(encoded));
    expect(decoded).toEqual(original);
  });

  it('accepts URL-safe alphabet', async () => {
    const decoded = new Uint8Array(decodeBase64url('-_8'));
    expect(decoded).toEqual(new Uint8Array([0xFB, 0xFF]));
  });

  it('accepts missing padding', async () => {
    // `SGVsbG8` → "Hello" (base64 would require
    // `SGVsbG8=`)
    const decoded = new Uint8Array(decodeBase64url('SGVsbG8'));
    expect(new TextDecoder().decode(decoded)).toBe('Hello');
  });

  it('decodes empty string to empty buffer', async () => {
    expect(decodeBase64url('').byteLength).toBe(0);
  });

  it('throws on characters outside the base64url alphabet', () => {
    // URL-safe substitution (`-` → `+`, `_` → `/`)
    // leaves other illegal chars alone, so atob
    // rejects them.
    expect(() => decodeBase64url('not base64!')).toThrow();
  });
});

describe('getRandom', () => {
  it('produces base64url strings of the expected length', async () => {
    // n bytes → ceil(n * 4 / 3) chars without padding
    expect(getRandom(3)).toHaveLength(4);
    expect(getRandom(9)).toHaveLength(12);
    expect(getRandom(16)).toHaveLength(22);
  });

  it('produces different values on repeat calls', async () => {
    const a = getRandom(16);
    const b = getRandom(16);
    expect(a).not.toBe(b);
  });

  it('produces URL-safe output (no +, /, =)', async () => {
    // Sample a lot to exercise the alphabet. Probability
    // of never hitting a substitution byte is negligible
    // for 1000×16 random bytes.
    for (let i = 0; i < 1000; i++) {
      const value = getRandom(16);
      expect(value).not.toMatch(/[+/=]/);
    }
  });

  it('throws RangeError on non-positive length', () => {
    expect(() => getRandom(0)).toThrow(RangeError);
    expect(() => getRandom(-1)).toThrow(RangeError);
  });

  it('throws RangeError on non-safe-integer length', () => {
    expect(() => getRandom(1.5)).toThrow(RangeError);
    expect(() => getRandom(Number.NaN)).toThrow(RangeError);
    expect(() => getRandom(Number.MAX_SAFE_INTEGER + 1)).toThrow(RangeError);
  });

  it('throws RangeError when length exceeds the 65 536-byte quota', () => {
    expect(() => getRandom(65_537)).toThrow(RangeError);
    // Boundary: exactly 65 536 is allowed.
    expect(getRandom(65_536)).toHaveLength(87_382);
  });
});
