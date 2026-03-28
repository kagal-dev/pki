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

  it('rejects missing alg', () => {
    const result = validateJWSProtectedHeader({
      kid: 'https://ca.example/acct/1',
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
