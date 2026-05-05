// RevokeCert schema tests (RFC 8555 §7.6)

import { describe, expect, it } from 'vitest';

import { validateRevokeCert } from '..';
import { crlReasonCodes } from '../../types/requests/revoke-cert';

describe('validateRevokeCert', () => {
  it('accepts certificate only', () => {
    const result = validateRevokeCert({
      certificate: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.certificate)
        .toBe('MIICYjCCAUoCAQAwHTEbMBkGA1UE');
    }
  });

  it('accepts with reason code', () => {
    const result = validateRevokeCert({
      certificate: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
      reason: 1,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.reason).toBe(1);
    }
  });

  it('rejects reason code 7 (not used)', () => {
    const result = validateRevokeCert({
      certificate: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
      reason: 7,
    });
    expect(result.success).toBe(false);
  });

  it('rejects out-of-range reason code', () => {
    const result = validateRevokeCert({
      certificate: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
      reason: 11,
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty certificate', () => {
    const result = validateRevokeCert({
      certificate: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64url certificate', () => {
    const result = validateRevokeCert({
      certificate: 'not valid!=+/',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing certificate', () => {
    const result = validateRevokeCert({});
    expect(result.success).toBe(false);
  });

  it('rejects unknown fields (strict schema)', () => {
    const result = validateRevokeCert({
      certificate: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
      extra: true,
    });
    expect(result.success).toBe(false);
  });

  it('accepts every valid reason code', () => {
    // RFC 5280 §5.3.1 — 0..6, 8, 9, 10 (7 reserved).
    // Iterate the canonical tuple so future additions
    // are automatically covered.
    for (const reason of crlReasonCodes) {
      const result = validateRevokeCert({
        certificate: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
        reason,
      });
      expect(result.success).toBe(true);
    }
  });

  it('rejects negative reason code', () => {
    const result = validateRevokeCert({
      certificate: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
      reason: -1,
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-integer reason code', () => {
    const result = validateRevokeCert({
      certificate: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
      reason: 1.5,
    });
    expect(result.success).toBe(false);
  });

  it('rejects string reason code', () => {
    // Picklist compares with `===`; '1' is not 1.
    const result = validateRevokeCert({
      certificate: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
      reason: '1',
    });
    expect(result.success).toBe(false);
  });
});
