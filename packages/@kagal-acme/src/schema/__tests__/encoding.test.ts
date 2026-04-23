// Encoding schema tests (RFC 7515 §2)

import { describe, expect, it } from 'vitest';

import {
  validateBase64url,
  validateBase64urlOrEmpty,
  validatePEM,
} from '..';

import { jsonNull } from './test-utils';

describe('validateBase64url', () => {
  it('accepts a valid base64url string', () => {
    const result = validateBase64url('abcd');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe('abcd');
    }
  });

  it('accepts URL-safe alphabet (- and _)', () => {
    const result = validateBase64url('-_8');
    expect(result.success).toBe(true);
  });

  it('accepts realistic base64url of SHA-256 length', () => {
    // 43 chars — 32-byte SHA-256 digest without padding.
    // This is the RFC 7638 §3.1 canonical RSA thumbprint.
    const result = validateBase64url(
      'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
    );
    expect(result.success).toBe(true);
  });

  it('rejects empty string', () => {
    const result = validateBase64url('');
    expect(result.success).toBe(false);
  });

  it('rejects length with remainder 1 mod 4', () => {
    // 5 chars: 5 % 4 = 1. Impossible in valid base64url —
    // the smallest encoded group is 2 chars for 1 byte.
    const result = validateBase64url('abcde');
    expect(result.success).toBe(false);
  });

  it('rejects single character (length 1 mod 4)', () => {
    const result = validateBase64url('a');
    expect(result.success).toBe(false);
  });

  it('accepts length with remainder 2 mod 4', () => {
    // 1 byte → 2 chars.
    const result = validateBase64url('ab');
    expect(result.success).toBe(true);
  });

  it('accepts length with remainder 3 mod 4', () => {
    // 2 bytes → 3 chars.
    const result = validateBase64url('abc');
    expect(result.success).toBe(true);
  });

  it('accepts length divisible by 4', () => {
    // 3 bytes → 4 chars (no padding).
    const result = validateBase64url('abcd');
    expect(result.success).toBe(true);
  });

  it('rejects padding character (=)', () => {
    const result = validateBase64url('abc=');
    expect(result.success).toBe(false);
  });

  it('rejects standard base64 `+` character', () => {
    const result = validateBase64url('ab+d');
    expect(result.success).toBe(false);
  });

  it('rejects standard base64 `/` character', () => {
    const result = validateBase64url('ab/d');
    expect(result.success).toBe(false);
  });

  it('rejects whitespace', () => {
    const result = validateBase64url('ab cd');
    expect(result.success).toBe(false);
  });

  it('rejects non-string input', () => {
    expect(validateBase64url(42).success).toBe(false);
    expect(validateBase64url(jsonNull).success).toBe(false);
    expect(validateBase64url(undefined).success).toBe(false);
    expect(validateBase64url(['abcd']).success).toBe(false);
    expect(validateBase64url({}).success).toBe(false);
  });
});

describe('validateBase64urlOrEmpty', () => {
  it('accepts empty string (POST-as-GET payload)', () => {
    const result = validateBase64urlOrEmpty('');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe('');
    }
  });

  it('accepts a valid base64url string', () => {
    const result = validateBase64urlOrEmpty('abcd');
    expect(result.success).toBe(true);
  });

  it('accepts URL-safe alphabet', () => {
    const result = validateBase64urlOrEmpty('-_8');
    expect(result.success).toBe(true);
  });

  it('rejects length with remainder 1 mod 4', () => {
    const result = validateBase64urlOrEmpty('abcde');
    expect(result.success).toBe(false);
  });

  it('rejects single character (length 1 mod 4)', () => {
    const result = validateBase64urlOrEmpty('a');
    expect(result.success).toBe(false);
  });

  it('rejects padding character (=)', () => {
    const result = validateBase64urlOrEmpty('abc=');
    expect(result.success).toBe(false);
  });

  it('rejects standard base64 `+` character', () => {
    const result = validateBase64urlOrEmpty('ab+d');
    expect(result.success).toBe(false);
  });

  it('rejects standard base64 `/` character', () => {
    const result = validateBase64urlOrEmpty('ab/d');
    expect(result.success).toBe(false);
  });

  it('rejects non-string input', () => {
    expect(validateBase64urlOrEmpty(42).success).toBe(false);
    expect(validateBase64urlOrEmpty(jsonNull).success)
      .toBe(false);
    expect(validateBase64urlOrEmpty(undefined).success)
      .toBe(false);
  });
});

// RFC 7468 §5.1 sample — minimal syntactically-valid
// PEM block. Shared across the happy-path tests below.
const samplePEMCertificate = [
  '-----BEGIN CERTIFICATE-----',
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo',
  '4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u',
  '-----END CERTIFICATE-----',
].join('\n');

const samplePEMMultiWord = [
  '-----BEGIN MULTI LINE LABEL-----',
  'UExBQ0VIT0xERVJQTEFDRUhPTERFUlBMQUNFSE9MREVSUExBQ0VIT0xERVJQTEFB',
  'UExBQ0VIT0xERVJQTEFDRUhPTERFUlBMQUNFSE9MREVSUExBQ0VIT0xERVJQTEFB',
  '-----END MULTI LINE LABEL-----',
].join('\n');

describe('validatePEM', () => {
  it('accepts a single certificate block', () => {
    const result = validatePEM(samplePEMCertificate);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe(samplePEMCertificate);
    }
  });

  it('accepts a key block with multi-word label', () => {
    const result = validatePEM(samplePEMMultiWord);
    expect(result.success).toBe(true);
  });

  it('accepts a concatenated chain', () => {
    const chain =
      samplePEMCertificate + '\n' + samplePEMCertificate;
    const result = validatePEM(chain);
    expect(result.success).toBe(true);
  });

  it('accepts a chain with trailing newline', () => {
    const result = validatePEM(samplePEMCertificate + '\n');
    expect(result.success).toBe(true);
  });

  it('rejects missing BEGIN marker', () => {
    const broken = samplePEMCertificate.replace(
      '-----BEGIN CERTIFICATE-----',
      '',
    );
    const result = validatePEM(broken);
    expect(result.success).toBe(false);
  });

  it('rejects missing END marker', () => {
    const broken = samplePEMCertificate.replace(
      '-----END CERTIFICATE-----',
      '',
    );
    const result = validatePEM(broken);
    expect(result.success).toBe(false);
  });

  it('accepts lowercase label (armour is structural only)', () => {
    // RFC 7468's label ABNF permits mixed case —
    // uppercase is convention, not requirement. Label
    // alphabet and per-type semantics are x509's
    // concern; the schema only confirms the armour
    // framing.
    const lowercased = samplePEMCertificate.replaceAll(
      'CERTIFICATE',
      'certificate',
    );
    const result = validatePEM(lowercased);
    expect(result.success).toBe(true);
  });

  it('rejects malformed markers (extra dashes)', () => {
    const broken = samplePEMCertificate.replace(
      '-----BEGIN',
      '------BEGIN',
    );
    const result = validatePEM(broken);
    expect(result.success).toBe(false);
  });

  it('rejects mismatched BEGIN/END labels', () => {
    // RFC 7468 §2 requires BEGIN and END labels to
    // match within a block — enforced via regex
    // backreference.
    const broken = samplePEMCertificate.replace(
      '-----END CERTIFICATE-----',
      '-----END PRIVATE KEY-----',
    );
    const result = validatePEM(broken);
    expect(result.success).toBe(false);
  });

  it('rejects empty string', () => {
    const result = validatePEM('');
    expect(result.success).toBe(false);
  });

  it('rejects bare base64 without armour', () => {
    const result = validatePEM('UExBQ0VIT0xERVI=');
    expect(result.success).toBe(false);
  });

  it('rejects non-string input', () => {
    expect(validatePEM(42).success).toBe(false);
    expect(validatePEM(jsonNull).success).toBe(false);
    expect(validatePEM(undefined).success).toBe(false);
    expect(validatePEM([samplePEMCertificate]).success)
      .toBe(false);
  });
});
