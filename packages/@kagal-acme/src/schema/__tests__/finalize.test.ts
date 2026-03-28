// Finalize schema tests (RFC 8555 §7.4)

import { describe, expect, it } from 'vitest';

import { validateFinalize } from '..';

describe('validateFinalize', () => {
  it('accepts a valid finalize payload', () => {
    const result = validateFinalize({
      csr: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.csr)
        .toBe('MIICYjCCAUoCAQAwHTEbMBkGA1UE');
    }
  });

  it('rejects empty CSR', () => {
    const result = validateFinalize({ csr: '' });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64url CSR', () => {
    const result = validateFinalize({
      csr: 'not valid!=+/',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing CSR', () => {
    const result = validateFinalize({});
    expect(result.success).toBe(false);
  });

  it('rejects unknown fields (strict schema)', () => {
    const result = validateFinalize({
      csr: 'MIICYjCCAUoCAQAwHTEbMBkGA1UE',
      extra: true,
    });
    expect(result.success).toBe(false);
  });
});
