// JWS schema tests (RFC 7515, RFC 8555 §6.2)

import { describe, expect, it } from 'vitest';

import {
  validateACMEProtectedHeader,
  validateACMERequestHeader,
  validateFlattenedJWS,
  validateJWSProtectedHeader,
} from '..';

describe('validateFlattenedJWS', () => {
  it('accepts a valid flattened JWS', () => {
    const result = validateFlattenedJWS({
      protected: 'eyJhbGciOiJFUzI1NiJ9',
      payload: 'eyJ0ZXN0IjoxfQ',
      signature: 'abc123',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.protected)
        .toBe('eyJhbGciOiJFUzI1NiJ9');
    }
  });

  it('rejects missing signature', () => {
    const result = validateFlattenedJWS({
      protected: 'eyJhbGciOiJFUzI1NiJ9',
      payload: 'eyJ0ZXN0IjoxfQ',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-string fields', () => {
    const result = validateFlattenedJWS({
      protected: 'eyJhbGciOiJFUzI1NiJ9',
      payload: 42,
      signature: 'abc123',
    });
    expect(result.success).toBe(false);
  });

  it('accepts empty payload (POST-as-GET)', () => {
    const result = validateFlattenedJWS({
      protected: 'eyJhbGciOiJFUzI1NiJ9',
      payload: '',
      signature: 'abc123',
    });
    expect(result.success).toBe(true);
  });

  it('rejects non-base64url protected', () => {
    const result = validateFlattenedJWS({
      protected: 'not valid!',
      payload: 'eyJ0ZXN0IjoxfQ',
      signature: 'abc123',
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty protected', () => {
    const result = validateFlattenedJWS({
      protected: '',
      payload: 'eyJ0ZXN0IjoxfQ',
      signature: 'abc123',
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty signature', () => {
    const result = validateFlattenedJWS({
      protected: 'eyJhbGciOiJFUzI1NiJ9',
      payload: 'eyJ0ZXN0IjoxfQ',
      signature: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown fields (strict schema)', () => {
    const result = validateFlattenedJWS({
      protected: 'eyJhbGciOiJFUzI1NiJ9',
      payload: 'eyJ0ZXN0IjoxfQ',
      signature: 'abc123',
      extra: true,
    });
    expect(result.success).toBe(false);
  });
});

const ecKey = {
  kty: 'EC' as const,
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1naHYmosIpo27Q-oICydDQ',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

describe('validateJWSProtectedHeader', () => {
  it('accepts minimal header (alg only)', () => {
    const result = validateJWSProtectedHeader({
      alg: 'ES256',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with jwk', () => {
    const result = validateJWSProtectedHeader({
      alg: 'ES256',
      jwk: ecKey,
    });
    expect(result.success).toBe(true);
  });

  it('accepts with kid', () => {
    const result = validateJWSProtectedHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with both jwk and kid', () => {
    const result = validateJWSProtectedHeader({
      alg: 'ES256',
      jwk: ecKey,
      kid: 'https://ca.example/acct/1',
    });
    expect(result.success).toBe(true);
  });

  it('accepts HS256 (EAB inner)', () => {
    // RFC 8555 §7.3.4 EAB uses MAC-based algorithms
    // — JWSProtectedHeader is used for the inner JWS.
    const result = validateJWSProtectedHeader({
      alg: 'HS256',
      kid: 'eab-key-id',
    });
    expect(result.success).toBe(true);
  });

  it('accepts EdDSA', () => {
    const result = validateJWSProtectedHeader({
      alg: 'EdDSA',
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing alg', () => {
    const result = validateJWSProtectedHeader({
      kid: 'https://ca.example/acct/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects alg: none', () => {
    // RFC 7518 registers `none` but ACME JWS always
    // carries a signature — the picklist excludes it
    // on purpose.
    const result = validateJWSProtectedHeader({
      alg: 'none',
    });
    expect(result.success).toBe(false);
  });

  it('rejects unregistered alg', () => {
    const result = validateJWSProtectedHeader({
      alg: 'HS999',
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty kid', () => {
    const result = validateJWSProtectedHeader({
      alg: 'ES256',
      kid: '',
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateJWSProtectedHeader({
      alg: 'ES256',
      typ: 'JWT',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as
          Record<string, unknown>).typ,
      ).toBe('JWT');
    }
  });
});

describe('validateACMEProtectedHeader', () => {
  it('accepts with nonce and url', () => {
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with jwk', () => {
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      jwk: ecKey,
      nonce: 'abc123',
      url: 'https://ca.example/new-acct',
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing nonce', () => {
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing url', () => {
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing alg', () => {
    const result = validateACMEProtectedHeader({
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects HS256 (MAC-based alg on outer JWS)', () => {
    // RFC 8555 §6.2 forbids MAC-based algorithms on
    // the outer ACME request. HS* is fine on the
    // inner JWSProtectedHeader (EAB, §7.3.4) but not
    // here.
    const result = validateACMEProtectedHeader({
      alg: 'HS256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects alg: none', () => {
    const result = validateACMEProtectedHeader({
      alg: 'none',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-URL kid', () => {
    // §6.2: kid MUST contain the account URL.
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      kid: 'not a url',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-URL url', () => {
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'not a url',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64url nonce', () => {
    // §6.5: nonce MUST be a base64url-encoded
    // octet string.
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'has space',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty nonce', () => {
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: '',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects nonce with standard-base64 `+`', () => {
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc+def',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateACMEProtectedHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
      crit: ['nonce'],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as
          Record<string, unknown>).crit,
      ).toEqual(['nonce']);
    }
  });
});

describe('validateACMERequestHeader', () => {
  it('accepts with jwk (no kid)', () => {
    const result = validateACMERequestHeader({
      alg: 'ES256',
      jwk: ecKey,
      nonce: 'abc123',
      url: 'https://ca.example/new-acct',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with kid (no jwk)', () => {
    const result = validateACMERequestHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(true);
  });

  it('rejects with both jwk and kid', () => {
    const result = validateACMERequestHeader({
      alg: 'ES256',
      jwk: ecKey,
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects with neither jwk nor kid', () => {
    const result = validateACMERequestHeader({
      alg: 'ES256',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing alg', () => {
    const result = validateACMERequestHeader({
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing nonce', () => {
    const result = validateACMERequestHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing url', () => {
    const result = validateACMERequestHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-URL kid', () => {
    const result = validateACMERequestHeader({
      alg: 'ES256',
      kid: 'not a url',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects HS256 (MAC-based alg on outer JWS)', () => {
    const result = validateACMERequestHeader({
      alg: 'HS256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64url nonce', () => {
    const result = validateACMERequestHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'has space',
      url: 'https://ca.example/order/1',
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateACMERequestHeader({
      alg: 'ES256',
      kid: 'https://ca.example/acct/1',
      nonce: 'abc123',
      url: 'https://ca.example/order/1',
      crit: ['nonce'],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as
          Record<string, unknown>).crit,
      ).toEqual(['nonce']);
    }
  });
});
