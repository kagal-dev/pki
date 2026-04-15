// KeyChange schema tests (RFC 8555 §7.3.5)

import { describe, expect, it } from 'vitest';

import { validateKeyChange } from '..';

/** EC P-256 (RFC 7517 Appendix A.1). */
const ecKey = {
  kty: 'EC' as const,
  crv: 'P-256',
  x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
  y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
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
        n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb' +
          'WhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc' +
          '_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY' +
          '4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0' +
          '_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZH' +
          'zu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhA' +
          'I4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIq' +
          'bw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
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
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
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
