// JWK schema tests (RFC 7517)

import { describe, expect, it } from 'vitest';

import { validateJWK } from '..';

describe('validateJWK', () => {
  it('accepts EC key', () => {
    const result = validateJWK({
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe',
      y: 'x_FEzRu9m36HLN_tue659L',
    });
    expect(result.success).toBe(true);
  });

  it('rejects EC key without y', () => {
    const result = validateJWK({
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe',
    });
    expect(result.success).toBe(false);
  });

  it('accepts OKP key', () => {
    const result = validateJWK({
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg',
    });
    expect(result.success).toBe(true);
  });

  it('accepts RSA key', () => {
    const result = validateJWK({
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZp',
      e: 'AQAB',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with optional base members', () => {
    const result = validateJWK({
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe',
      y: 'x_FEzRu9m36HLN_tue659L',
      kid: 'key-1',
      alg: 'ES256',
      use: 'sig',
    });
    expect(result.success).toBe(true);
  });

  it('rejects unknown kty', () => {
    const result = validateJWK({
      kty: 'UNKNOWN',
      x: 'test',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing kty', () => {
    const result = validateJWK({
      crv: 'P-256',
      x: 'test',
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateJWK({
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe',
      y: 'x_FEzRu9m36HLN_tue659L',
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
