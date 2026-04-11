// KeyChange schema tests (RFC 8555 §7.3.5)

import { describe, expect, it } from 'vitest';

import { validateKeyChange } from '..';

const ecKey = {
  kty: 'EC' as const,
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe',
  y: 'x_FEzRu9m36HLN_tue659L',
};

describe('validateKeyChange', () => {
  it('accepts with EC key', () => {
    const result = validateKeyChange({
      account:
        'https://example.com/acme/acct/1',
      oldKey: ecKey,
    });
    expect(result.success).toBe(true);
  });

  it('accepts with RSA key', () => {
    const result = validateKeyChange({
      account:
        'https://example.com/acme/acct/1',
      oldKey: {
        kty: 'RSA',
        n: '0vx7agoebGcQSuuPiLJXZp',
        e: 'AQAB',
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts with OKP key', () => {
    const result = validateKeyChange({
      account:
        'https://example.com/acme/acct/1',
      oldKey: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: '11qYAYKxCrfVS_7TyWQHOg',
      },
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing account', () => {
    const result = validateKeyChange({
      oldKey: ecKey,
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing oldKey', () => {
    const result = validateKeyChange({
      account:
        'https://example.com/acme/acct/1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown fields (strict)', () => {
    const result = validateKeyChange({
      account:
        'https://example.com/acme/acct/1',
      oldKey: ecKey,
      extra: true,
    });
    expect(result.success).toBe(false);
  });
});
