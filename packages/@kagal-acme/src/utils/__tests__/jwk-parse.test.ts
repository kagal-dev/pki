// JWK parse + WebCrypto export tests (RFC 7517).

import { describe, expect, expectTypeOf, it } from 'vitest';

import type { JWK } from '../../types/jws/jwk';
import { exportJWK, parseJWK } from '..';
import { jsonNull } from './test-utils';

describe('parseJWK', () => {
  it('parses a valid EC JWK and brands coords', () => {
    const out = parseJWK({
      kty: 'EC',
      crv: 'P-256',
      x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
      y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
    });
    expectTypeOf<typeof out>().toEqualTypeOf<JWK>();
    expect(out.kty).toBe('EC');
  });

  it('parses a valid RSA JWK', () => {
    const out = parseJWK({
      kty: 'RSA',
      n: 'n-value',
      e: 'AQAB',
    });
    expect(out.kty).toBe('RSA');
  });

  it('throws TypeError on unknown kty', () => {
    expect(() => parseJWK({ kty: 'bogus' })).toThrow(TypeError);
  });

  it('throws TypeError on missing required member', () => {
    expect(() => parseJWK({ kty: 'EC', crv: 'P-256' }))
      .toThrow(TypeError);
  });

  it('throws TypeError on non-base64url coord', () => {
    expect(() => parseJWK({
      kty: 'EC',
      crv: 'P-256',
      x: 'not base64url!',
      y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
    })).toThrow(TypeError);
  });

  it('throws TypeError on non-object input', () => {
    expect(() => parseJWK(jsonNull)).toThrow(TypeError);
    expect(() => parseJWK('jwk-as-string')).toThrow(TypeError);
    expect(() => parseJWK(undefined)).toThrow(TypeError);
  });
});

describe('exportJWK', () => {
  it('exports an ECDSA P-256 public key as branded JWK', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const out = await exportJWK(pair.publicKey);
    expectTypeOf<typeof out>().toEqualTypeOf<JWK>();
    expect(out.kty).toBe('EC');
    if (out.kty === 'EC') {
      expect(out.crv).toBe('P-256');
    }
  });

  it('exports an RSA public key as branded JWK', async () => {
    const pair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    );
    const out = await exportJWK(pair.publicKey);
    expect(out.kty).toBe('RSA');
  });

  it('propagates DOMException on non-extractable keys', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    );
    await expect(exportJWK(pair.publicKey)).resolves.toBeDefined();
    await expect(exportJWK(pair.privateKey)).rejects.toThrow();
  });
});
