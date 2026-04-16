// Identifier schema tests (RFC 8555 §9.7.7)

import { describe, expect, it } from 'vitest';

import { validateIdentifier } from '..';
import { jsonNull } from './test-utils';

describe('validateIdentifier — dns', () => {
  it('accepts a simple dns identifier', () => {
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

  it('accepts multi-label dns names', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: 'sub.domain.example.co.uk',
    });
    expect(result.success).toBe(true);
  });

  it('accepts wildcard dns names', () => {
    // RFC 8555 §7.1.3 — wildcard orders use `*.` prefix.
    const result = validateIdentifier({
      type: 'dns',
      value: '*.example.com',
    });
    expect(result.success).toBe(true);
  });

  it('accepts punycode-encoded IDN labels', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: 'xn--nxasmq6b.example.com',
    });
    expect(result.success).toBe(true);
  });

  it('accepts labels with internal hyphens', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: 'my-host.example-domain.com',
    });
    expect(result.success).toBe(true);
  });

  it('rejects empty value', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects value with whitespace', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: 'ex ample.com',
    });
    expect(result.success).toBe(false);
  });

  it('rejects leading-hyphen label', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: '-leading.example.com',
    });
    expect(result.success).toBe(false);
  });

  it('rejects trailing-hyphen label', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: 'trailing-.example.com',
    });
    expect(result.success).toBe(false);
  });

  it('rejects trailing dot', () => {
    // Wire form is normalised without the trailing
    // root dot; the CA receives preferred-name form.
    const result = validateIdentifier({
      type: 'dns',
      value: 'example.com.',
    });
    expect(result.success).toBe(false);
  });

  it('rejects mid-name wildcard', () => {
    // Only leading `*.` is allowed.
    const result = validateIdentifier({
      type: 'dns',
      value: 'sub.*.example.com',
    });
    expect(result.success).toBe(false);
  });

  it('rejects an IP address as dns value', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: '192.0.2.1',
    });
    expect(result.success).toBe(false);
  });
});

describe('validateIdentifier — ip', () => {
  it('accepts IPv4 dotted-decimal', () => {
    const result = validateIdentifier({
      type: 'ip',
      value: '192.0.2.1',
    });
    expect(result.success).toBe(true);
  });

  it('accepts IPv6 full form', () => {
    const result = validateIdentifier({
      type: 'ip',
      value: '2001:db8:0:0:0:0:0:1',
    });
    expect(result.success).toBe(true);
  });

  it('accepts IPv6 compressed form', () => {
    const result = validateIdentifier({
      type: 'ip',
      value: '2001:db8::1',
    });
    expect(result.success).toBe(true);
  });

  it('accepts IPv6 loopback', () => {
    const result = validateIdentifier({
      type: 'ip',
      value: '::1',
    });
    expect(result.success).toBe(true);
  });

  it('accepts non-RFC-5952-canonical IPv6 forms', () => {
    // Schema accepts any RFC 4291 textual form —
    // RFC 5952 canonicalisation (lowercase hex,
    // no leading zeros, longest-run `::` compression)
    // is deferred to `/utils` or the consumer. This
    // test documents the contract.
    for (const value of [
      '2001:DB8::1', // uppercase hex
      '2001:0db8:0000:0000::1', // leading zeros
      '2001:db8:0:0:0:0:0:1', // no `::` compression
    ]) {
      const result = validateIdentifier({ type: 'ip', value });
      expect(result.success).toBe(true);
    }
  });

  it('rejects out-of-range IPv4 octet', () => {
    const result = validateIdentifier({
      type: 'ip',
      value: '999.0.2.1',
    });
    expect(result.success).toBe(false);
  });

  it('rejects a dns name as ip value', () => {
    const result = validateIdentifier({
      type: 'ip',
      value: 'example.com',
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty value', () => {
    const result = validateIdentifier({
      type: 'ip',
      value: '',
    });
    expect(result.success).toBe(false);
  });
});

describe('validateIdentifier — structural', () => {
  it('rejects unknown identifier type', () => {
    const result = validateIdentifier({
      type: 'email',
      value: 'user@example.com',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing type', () => {
    const result = validateIdentifier({
      value: 'example.com',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing value (dns)', () => {
    const result = validateIdentifier({ type: 'dns' });
    expect(result.success).toBe(false);
  });

  it('rejects missing value (ip)', () => {
    const result = validateIdentifier({ type: 'ip' });
    expect(result.success).toBe(false);
  });

  it('rejects non-object inputs', () => {
    expect(validateIdentifier(42).success).toBe(false);
    expect(validateIdentifier('example.com').success)
      .toBe(false);
    expect(validateIdentifier(undefined).success)
      .toBe(false);
    expect(validateIdentifier(jsonNull).success).toBe(false);
    expect(validateIdentifier([]).success).toBe(false);
  });

  it('preserves unknown fields on wire (dns)', () => {
    const result = validateIdentifier({
      type: 'dns',
      value: 'example.com',
      extra: true,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as
          Record<string, unknown>).extra,
      ).toBe(true);
    }
  });
});
