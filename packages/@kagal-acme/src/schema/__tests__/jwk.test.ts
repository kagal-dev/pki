// JWK schema tests (RFC 7517)

import { describe, expect, it } from 'vitest';

import { validateJWK } from '..';

import { jsonNull } from './test-utils';

// -- test vectors --

/** EC P-256 (RFC 7517 Appendix A.1). */
const ecP256 = {
  kty: 'EC',
  crv: 'P-256',
  x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
  y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
};

/** OKP Ed25519 (RFC 8032 §7.1 test 1 public key). */
const okpEd25519 = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
};

/** RSA (RFC 7638 §3.1 modulus + public exponent). */
const rsa = {
  kty: 'RSA',
  n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb' +
    'WhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc' +
    '_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY' +
    '4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0' +
    '_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZH' +
    'zu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhA' +
    'I4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIq' +
    'bw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  // cspell:disable-next-line
  e: 'AQAB',
};

describe('validateJWK — accept (positive)', () => {
  it('accepts EC P-256 key', () => {
    expect(validateJWK(ecP256).success).toBe(true);
  });

  it('accepts EC P-384 key', () => {
    // Coordinates faked to the right length (64 chars
    // of unpadded base64url = 48-byte P-384 x/y).
    // Schema cares only about base64url framing.
    const result = validateJWK({
      kty: 'EC',
      crv: 'P-384',
      x: 'A'.repeat(64),
      y: 'B'.repeat(64),
    });
    expect(result.success).toBe(true);
  });

  it('accepts EC P-521 key', () => {
    const result = validateJWK({
      kty: 'EC',
      crv: 'P-521',
      x: 'A'.repeat(88),
      y: 'B'.repeat(88),
    });
    expect(result.success).toBe(true);
  });

  it('accepts OKP Ed25519 key', () => {
    expect(validateJWK(okpEd25519).success).toBe(true);
  });

  it('accepts OKP Ed448 key', () => {
    const result = validateJWK({
      kty: 'OKP',
      crv: 'Ed448',
      x: 'A'.repeat(76),
    });
    expect(result.success).toBe(true);
  });

  it('accepts OKP X25519 key', () => {
    const result = validateJWK({
      ...okpEd25519,
      crv: 'X25519',
    });
    expect(result.success).toBe(true);
  });

  it('accepts OKP X448 key', () => {
    const result = validateJWK({
      kty: 'OKP',
      crv: 'X448',
      x: 'A'.repeat(76),
    });
    expect(result.success).toBe(true);
  });

  it('accepts RSA key', () => {
    expect(validateJWK(rsa).success).toBe(true);
  });

  it('accepts optional base members', () => {
    const result = validateJWK({
      ...ecP256,
      'kid': 'key-1',
      'alg': 'ES256',
      'use': 'sig',
      'key_ops': ['sign', 'verify'],
      'x5u': 'https://example.com/cert.pem',
      'x5c': ['MIIBIjANBgkqhkiG9w0BAQ=='],
      // cspell:disable-next-line
      'x5t': 'dGh1bWJwcmludA',
      'x5t#S256': 'dGh1bWJwcmludFMyNTY',
    });
    expect(result.success).toBe(true);
  });

  it('preserves unknown wire-extension fields', () => {
    const result = validateJWK({
      ...ecP256,
      futureField: 'preserved',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as
          Record<string, unknown>)
          .futureField,
      ).toBe('preserved');
    }
  });
});

describe('validateJWK — reject (negative)', () => {
  // -- structural --

  it('rejects unknown kty', () => {
    const result = validateJWK({
      kty: 'UNKNOWN',
      x: 'dGVzdA',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing kty', () => {
    const result = validateJWK({
      crv: 'P-256',
      x: ecP256.x,
    });
    expect(result.success).toBe(false);
  });

  it('rejects EC key without y', () => {
    // y is required for EC (RFC 7518 §6.2.1.3).
    const result = validateJWK({
      kty: 'EC',
      crv: 'P-256',
      x: ecP256.x,
    });
    expect(result.success).toBe(false);
  });

  it('rejects RSA key without e', () => {
    const result = validateJWK({
      kty: 'RSA',
      n: rsa.n,
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-object inputs', () => {
    expect(validateJWK(42).success).toBe(false);
    expect(validateJWK('string').success).toBe(false);
    expect(validateJWK(jsonNull).success).toBe(false);
    expect(validateJWK(undefined).success).toBe(false);
    expect(validateJWK([]).success).toBe(false);
  });

  // -- crv picklist (defends against cross-kty mix-up) --

  it('rejects EC with OKP curve (crv=Ed25519)', () => {
    const result = validateJWK({
      ...ecP256,
      crv: 'Ed25519',
    });
    expect(result.success).toBe(false);
  });

  it('rejects OKP with EC curve (crv=P-256)', () => {
    const result = validateJWK({
      ...okpEd25519,
      crv: 'P-256',
    });
    expect(result.success).toBe(false);
  });

  it('rejects EC with unregistered crv', () => {
    const result = validateJWK({
      ...ecP256,
      crv: 'P-192',
    });
    expect(result.success).toBe(false);
  });

  it('rejects OKP with unregistered crv', () => {
    const result = validateJWK({
      ...okpEd25519,
      crv: 'Curve25519',
    });
    expect(result.success).toBe(false);
  });

  // -- base64url on coordinates --

  it('rejects EC with empty x', () => {
    const result = validateJWK({ ...ecP256, x: '' });
    expect(result.success).toBe(false);
  });

  it('rejects EC with empty y', () => {
    const result = validateJWK({ ...ecP256, y: '' });
    expect(result.success).toBe(false);
  });

  it('rejects EC with non-base64url chars in x', () => {
    const result = validateJWK({
      ...ecP256,
      x: 'has spaces in it',
    });
    expect(result.success).toBe(false);
  });

  it('rejects EC with standard base64 `+` in y', () => {
    const result = validateJWK({
      ...ecP256,
      y: 'abc+def',
    });
    expect(result.success).toBe(false);
  });

  it('rejects EC with padding `=` in x', () => {
    const result = validateJWK({
      ...ecP256,
      x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D=',
    });
    expect(result.success).toBe(false);
  });

  it('rejects EC with impossible length (mod 4 === 1)', () => {
    // Any base64url length `% 4 === 1` is impossible —
    // the smallest encoded group is 2 chars for 1 byte.
    const result = validateJWK({
      ...ecP256,
      x: 'f83OJ3D2xF1Bg8vub9tLe',
    });
    expect(result.success).toBe(false);
  });

  it('rejects OKP with empty x', () => {
    const result = validateJWK({
      ...okpEd25519,
      x: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects OKP with non-base64url alphabet', () => {
    const result = validateJWK({
      ...okpEd25519,
      x: '11qYAYKxCrfVS/7TyWQHOg',
    });
    expect(result.success).toBe(false);
  });

  it('rejects RSA with empty n', () => {
    const result = validateJWK({ ...rsa, n: '' });
    expect(result.success).toBe(false);
  });

  it('rejects RSA with empty e', () => {
    const result = validateJWK({ ...rsa, e: '' });
    expect(result.success).toBe(false);
  });

  it('rejects RSA with non-base64url chars in n', () => {
    const result = validateJWK({
      ...rsa,
      n: 'not a base64url string',
    });
    expect(result.success).toBe(false);
  });

  it('rejects RSA with impossible-length e', () => {
    // `Q` alone is 1 char, `% 4 === 1`.
    const result = validateJWK({ ...rsa, e: 'Q' });
    expect(result.success).toBe(false);
  });

  // -- coord type (not a string) --

  it('rejects EC with numeric x', () => {
    const result = validateJWK({ ...ecP256, x: 42 });
    expect(result.success).toBe(false);
  });

  it('rejects RSA with array n', () => {
    const result = validateJWK({ ...rsa, n: [rsa.n] });
    expect(result.success).toBe(false);
  });
});
