// CSR schema tests (RFC 2986, RFC 8555 §7.4)

import { describe, expect, it } from 'vitest';

import {
  validateCSR,
  validateDistinguishedName,
} from '..';

import { jsonNull } from './test-utils';

/** Minimum valid JWK for use as `subjectPublicKey`. */
const validPublicKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
  y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
};

describe('validateCSR — accept', () => {
  it('accepts a minimal CSR shape', () => {
    const result = validateCSR({
      subject: [],
      subjectPublicKey: validPublicKey,
      sans: [{ type: 'dns', value: 'example.com' }],
      der: new Uint8Array([1, 2, 3]),
    });
    expect(result.success).toBe(true);
  });

  it('accepts a populated DistinguishedName', () => {
    const result = validateCSR({
      subject: [
        { CN: ['example.com'] },
        { O: ['Example Co'], C: ['US'] },
      ],
      subjectPublicKey: validPublicKey,
      sans: [],
      der: new Uint8Array(),
    });
    expect(result.success).toBe(true);
  });

  it('accepts mixed dns + ip SANs', () => {
    const result = validateCSR({
      subject: [],
      subjectPublicKey: validPublicKey,
      sans: [
        { type: 'dns', value: 'example.com' },
        { type: 'ip', value: '192.0.2.1' },
        { type: 'ip', value: '2001:db8::1' },
      ],
      der: new Uint8Array(),
    });
    expect(result.success).toBe(true);
  });
});

describe('validateCSR — reject', () => {
  it('rejects a non-dns/ip SAN type', () => {
    const result = validateCSR({
      subject: [],
      subjectPublicKey: validPublicKey,
      sans: [{ type: 'email', value: 'me@example.com' }],
      der: new Uint8Array(),
    });
    expect(result.success).toBe(false);
  });

  it('rejects a non-Uint8Array der', () => {
    const result = validateCSR({
      subject: [],
      subjectPublicKey: validPublicKey,
      sans: [],
      der: [1, 2, 3],
    });
    expect(result.success).toBe(false);
  });

  it('rejects an invalid subjectPublicKey', () => {
    const result = validateCSR({
      subject: [],
      subjectPublicKey: { kty: 'bogus' },
      sans: [],
      der: new Uint8Array(),
    });
    expect(result.success).toBe(false);
  });

  it('rejects a missing field', () => {
    const result = validateCSR({
      subject: [],
      subjectPublicKey: validPublicKey,
      sans: [],
      // der missing
    });
    expect(result.success).toBe(false);
  });

  it('rejects an unknown field (strictObject)', () => {
    const result = validateCSR({
      subject: [],
      subjectPublicKey: validPublicKey,
      sans: [],
      der: new Uint8Array(),
      extra: 'nope',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-object input', () => {
    expect(validateCSR(jsonNull).success).toBe(false);
    expect(validateCSR('csr-as-string').success).toBe(false);
    expect(validateCSR(undefined).success).toBe(false);
  });
});

describe('validateDistinguishedName — accept', () => {
  it('accepts an empty DN', () => {
    expect(validateDistinguishedName([]).success).toBe(true);
  });

  it('accepts a single-RDN DN', () => {
    const result = validateDistinguishedName([
      { CN: ['example.com'] },
    ]);
    expect(result.success).toBe(true);
  });

  it('accepts a multi-RDN DN with multi-valued attributes', () => {
    const result = validateDistinguishedName([
      { CN: ['example.com'] },
      { O: ['Example Co'], OU: ['Eng', 'Ops'], C: ['US'] },
    ]);
    expect(result.success).toBe(true);
  });
});

describe('validateDistinguishedName — reject', () => {
  it('rejects a non-array outer shape', () => {
    expect(validateDistinguishedName({}).success).toBe(false);
    expect(validateDistinguishedName('CN=example.com').success).toBe(false);
    expect(validateDistinguishedName(jsonNull).success).toBe(false);
  });

  it('rejects an RDN whose values are not arrays of strings', () => {
    const result = validateDistinguishedName([
      { CN: 'example.com' },
    ]);
    expect(result.success).toBe(false);
  });

  it('rejects an RDN whose value array contains non-strings', () => {
    const result = validateDistinguishedName([
      { CN: ['example.com', 42] },
    ]);
    expect(result.success).toBe(false);
  });
});
