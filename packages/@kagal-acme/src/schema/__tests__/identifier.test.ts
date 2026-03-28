// Identifier schema tests (RFC 8555 §9.7.7)

import { describe, expect, it } from 'vitest';

import { validateIdentifier } from '..';

describe('validateIdentifier', () => {
  it('accepts a dns identifier', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: 'example.com',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.type).toBe('dns');
      expect(result.data.value).toBe('example.com');
    }
  });

  it('accepts an ip identifier', () => {
    const result = validateIdentifier({
      type: 'ip',
      value: '192.0.2.1',
    });
    expect(result.success).toBe(true);
  });

  it('rejects unknown identifier type', () => {
    const result = validateIdentifier({
      type: 'email',
      value: 'user@example.com',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing value', () => {
    const result = validateIdentifier({ type: 'dns' });
    expect(result.success).toBe(false);
  });

  it('rejects empty value', () => {
    const result = validateIdentifier({ type: 'dns', value: '' });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: 'example.com',
      extra: true,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as unknown as Record<string, unknown>).extra)
        .toBe(true);
    }
  });
});
