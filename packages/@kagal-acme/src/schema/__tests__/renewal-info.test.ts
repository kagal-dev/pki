// RenewalInfo schema tests (RFC 9773)

import { describe, expect, it } from 'vitest';

import { validateCertID, validateRenewalInfo } from '..';

describe('validateRenewalInfo', () => {
  it('accepts a valid renewal info', () => {
    const result = validateRenewalInfo({
      suggestedWindow: {
        start: '2026-04-01T00:00:00Z',
        end: '2026-04-02T00:00:00Z',
      },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.suggestedWindow.start)
        .toBe('2026-04-01T00:00:00Z');
    }
  });

  it('accepts with explanationURL', () => {
    const result = validateRenewalInfo({
      suggestedWindow: {
        start: '2026-04-01T00:00:00Z',
        end: '2026-04-02T00:00:00Z',
      },
      explanationURL: 'https://ca.example/renew',
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing suggestedWindow', () => {
    const result = validateRenewalInfo({});
    expect(result.success).toBe(false);
  });

  it('rejects non-timestamp strings', () => {
    const result = validateRenewalInfo({
      suggestedWindow: {
        start: 'not-a-date',
        end: '2026-04-02T00:00:00Z',
      },
    });
    expect(result.success).toBe(false);
  });

  it('rejects start >= end', () => {
    const result = validateRenewalInfo({
      suggestedWindow: {
        start: '2026-04-02T00:00:00Z',
        end: '2026-04-01T00:00:00Z',
      },
    });
    expect(result.success).toBe(false);
  });

  it('rejects equal start and end', () => {
    const result = validateRenewalInfo({
      suggestedWindow: {
        start: '2026-04-01T00:00:00Z',
        end: '2026-04-01T00:00:00Z',
      },
    });
    expect(result.success).toBe(false);
  });

  it('rejects incomplete suggestedWindow', () => {
    const result = validateRenewalInfo({
      suggestedWindow: {
        start: '2026-04-01T00:00:00Z',
      },
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateRenewalInfo({
      suggestedWindow: {
        start: '2026-04-01T00:00:00Z',
        end: '2026-04-02T00:00:00Z',
      },
      retryAfter: 3600,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as Record<string, unknown>).retryAfter,
      ).toBe(3600);
    }
  });
});

describe('validateCertID', () => {
  it('accepts a valid certID', () => {
    const result = validateCertID(
      'aYhba4dGQEHBKIMhAbKqAw.AAABfnE',
    );
    expect(result.success).toBe(true);
  });

  it('rejects missing dot separator', () => {
    const result = validateCertID(
      'aYhba4dGQEHBKIMhAbKqAw',
    );
    expect(result.success).toBe(false);
  });

  it('rejects empty AKI segment', () => {
    const result = validateCertID('.AAABfnE');
    expect(result.success).toBe(false);
  });

  it('rejects empty serial segment', () => {
    const result = validateCertID(
      'aYhba4dGQEHBKIMhAbKqAw.',
    );
    expect(result.success).toBe(false);
  });

  it('rejects non-base64url characters', () => {
    const result = validateCertID('invalid!=.data');
    expect(result.success).toBe(false);
  });

  it('rejects empty string', () => {
    const result = validateCertID('');
    expect(result.success).toBe(false);
  });
});
