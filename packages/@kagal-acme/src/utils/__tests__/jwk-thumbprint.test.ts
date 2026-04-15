// JWK thumbprint tests (RFC 7638)

import { describe, expect, it } from 'vitest';

import type {
  ECJWK,
  JWK,
  OKPJWK,
  RSAJWK,
} from '../../types/jws/jwk';
import { jwkThumbprint } from '..';
import { validateJWK } from '../../schema';
import { asBase64url } from '../../types/encoding';

// -- test vectors --

/** EC P-256 (RFC 7517 Appendix A.1). */
const ecP256KeyA: ECJWK = {
  kty: 'EC',
  crv: 'P-256',
  x: asBase64url('MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4'),
  y: asBase64url('4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM'),
};

/** EC P-256 (RFC 7518 Appendix A.3). */
const ecP256KeyB: ECJWK = {
  kty: 'EC',
  crv: 'P-256',
  x: asBase64url('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU'),
  y: asBase64url('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0'),
};

/** OKP Ed25519 (RFC 8032 §7.1 test 1, 32-byte public key). */
const okpEd25519Key: OKPJWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: asBase64url('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'),
};

/** RSA key (RFC 7638 §3.1 canonical thumbprint example). */
const rsaKey: RSAJWK = {
  kty: 'RSA',
  n: asBase64url(
    '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb' +
    'WhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc' +
    '_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY' +
    '4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0' +
    '_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZH' +
    'zu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhA' +
    'I4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIq' +
    'bw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  ),
  e: asBase64url('AQAB'),
};

describe('jwkThumbprint', () => {
  it('matches the RFC 7638 §3.1 RSA test vector', async () => {
    // The canonical example — extra members `alg` and
    // `kid` MUST be excluded from the thumbprint input.
    const thumb = await jwkThumbprint({
      ...rsaKey,
      alg: 'RS256',
      kid: '2011-04-29',
    });
    expect(thumb)
      .toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });

  it('canonicalises OKP keys (crv, kty, x; lex order)', async () => {
    // No published RFC test vector for OKP thumbprints —
    // assert structural properties: deterministic and
    // independent of input member ordering / extras.
    const a = await jwkThumbprint(okpEd25519Key);
    const b = await jwkThumbprint({
      ...okpEd25519Key,
      kid: 'noise',
      alg: 'EdDSA',
    });
    expect(a).toBe(b);
    expect(a).toHaveLength(43);
  });

  it('is deterministic for EC P-256 keys', async () => {
    const a = await jwkThumbprint(ecP256KeyA);
    const b = await jwkThumbprint(ecP256KeyA);
    expect(a).toBe(b);
    // SHA-256 → 32 bytes → 43 base64url chars (no padding)
    expect(a).toHaveLength(43);
  });

  it('ignores optional base members (kid, alg, use, x5c, …)', async () => {
    const bare = await jwkThumbprint(ecP256KeyA);
    const decorated = await jwkThumbprint({
      ...ecP256KeyA,
      kid: 'key-1',
      alg: 'ES256',
      use: 'sig',
      key_ops: ['sign'],
      x5c: ['MIIB...'],
    });
    expect(bare).toBe(decorated);
  });

  it('drops wire extension members surfaced by looseObject', async () => {
    // The schema's `looseObject` lets unknown wire fields
    // through; the JWK type narrows them out at the type
    // level but they survive on the runtime object.
    // jwkThumbprint must hash only the required members.
    const result = validateJWK({
      ...ecP256KeyA,
      futureField: 'should not affect thumbprint',
    });
    if (!result.success) throw new Error('schema rejected valid JWK');

    const withWireExtras = await jwkThumbprint(result.data);
    const bare = await jwkThumbprint(ecP256KeyA);
    expect(withWireExtras).toBe(bare);
  });

  it('distinguishes EC keys with different coordinates', async () => {
    const a = await jwkThumbprint(ecP256KeyA);
    const b = await jwkThumbprint(ecP256KeyB);
    expect(a).not.toBe(b);
  });

  it('is insensitive to input member order', async () => {
    // Canonical form is always crv, kty, x, y — so
    // feeding the same required members in any order
    // must hash to the same value.
    const ordered = await jwkThumbprint(ecP256KeyA);
    const scrambled = await jwkThumbprint({
      y: ecP256KeyA.y,
      x: ecP256KeyA.x,
      kty: 'EC',
      crv: 'P-256',
    });
    expect(ordered).toBe(scrambled);
  });

  it('throws on unknown kty (runtime type bypass)', async () => {
    // Simulate a type-system bypass: a value with a
    // kty that isn't in the JWK union reaches
    // canonicalJWK. The default branch must throw so
    // the caller doesn't hash `undefined` → a garbage
    // thumbprint.
    await expect(
      jwkThumbprint({ kty: 'unknown' } as unknown as JWK),
    ).rejects.toThrow(/unsupported JWK kty: unknown/);
  });

  it('throws on EC JWK with a missing required member', async () => {
    // A type-system bypass that reaches canonicalJWK
    // with crv absent. JSON.stringify would silently
    // drop `undefined`, yielding a deterministic but
    // invalid thumbprint — reject instead.
    await expect(
      jwkThumbprint({
        kty: 'EC',
        x: ecP256KeyA.x,
        y: ecP256KeyA.y,
      } as unknown as JWK),
    ).rejects.toThrow(/member "crv" must be a non-empty string/);
  });

  it('throws on OKP JWK with a missing required member', async () => {
    await expect(
      jwkThumbprint({
        kty: 'OKP',
        crv: 'Ed25519',
      } as unknown as JWK),
    ).rejects.toThrow(/member "x" must be a non-empty string/);
  });

  it('throws on RSA JWK with a missing required member', async () => {
    await expect(
      jwkThumbprint({
        kty: 'RSA',
        e: rsaKey.e,
      } as unknown as JWK),
    ).rejects.toThrow(/member "n" must be a non-empty string/);
  });
});
