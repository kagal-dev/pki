// Account schema tests (RFC 8555 §7.1.2)

import { describe, expect, it } from 'vitest';

import { validateAccount } from '..';

describe('validateAccount', () => {
  it('accepts a minimal valid account', () => {
    const result = validateAccount({
      status: 'valid',
      orders: 'https://ca.example/acct/1/orders',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status).toBe('valid');
    }
  });

  it('accepts a full account', () => {
    const result = validateAccount({
      status: 'valid',
      contact: ['mailto:admin@example.com'],
      termsOfServiceAgreed: true,
      orders: 'https://ca.example/acct/1/orders',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.contact).toEqual(
        ['mailto:admin@example.com'],
      );
    }
  });

  it('accepts with external account binding', () => {
    const result = validateAccount({
      status: 'valid',
      orders: 'https://ca.example/acct/1/orders',
      externalAccountBinding: {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        payload: 'eyJrdHkiOiJFQyJ9',
        signature: 'hmac-sig',
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts deactivated status', () => {
    const result = validateAccount({
      status: 'deactivated',
      orders: 'https://ca.example/acct/1/orders',
    });
    expect(result.success).toBe(true);
  });

  it('accepts revoked status', () => {
    const result = validateAccount({
      status: 'revoked',
      orders: 'https://ca.example/acct/1/orders',
    });
    expect(result.success).toBe(true);
  });

  it('rejects unknown status', () => {
    const result = validateAccount({
      status: 'pending',
      orders: 'https://ca.example/acct/1/orders',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing status', () => {
    const result = validateAccount({
      contact: ['mailto:admin@example.com'],
      orders: 'https://ca.example/acct/1/orders',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing orders', () => {
    const result = validateAccount({
      status: 'valid',
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateAccount({
      status: 'valid',
      orders: 'https://ca.example/acct/1/orders',
      createdAt: '2026-01-01T00:00:00Z',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as Record<string, unknown>)
          .createdAt,
      ).toBe('2026-01-01T00:00:00Z');
    }
  });
});
