// Problem schema tests (RFC 7807)

import { describe, expect, it } from 'vitest';

import { validateProblem, validateSubproblem } from '..';

describe('validateSubproblem', () => {
  it('accepts a minimal subproblem', () => {
    const result = validateSubproblem({
      type: 'urn:ietf:params:acme:error:malformed',
    });
    expect(result.success).toBe(true);
  });

  it('accepts a full subproblem', () => {
    const result = validateSubproblem({
      type: 'urn:ietf:params:acme:error:rejectedIdentifier',
      title: 'Rejected Identifier',
      detail: 'Identifier rejected',
      status: 403,
      instance: 'https://ca.example/error/1',
      identifier: { type: 'dns', value: 'evil.example' },
    });
    expect(result.success).toBe(true);
  });

  it('rejects non-integer status', () => {
    const result = validateSubproblem({
      type: 'urn:ietf:params:acme:error:malformed',
      status: 403.5,
    });
    expect(result.success).toBe(false);
  });

  it('rejects status below 100', () => {
    const result = validateSubproblem({
      type: 'urn:ietf:params:acme:error:malformed',
      status: 99,
    });
    expect(result.success).toBe(false);
  });

  it('rejects status above 599', () => {
    const result = validateSubproblem({
      type: 'urn:ietf:params:acme:error:malformed',
      status: 600,
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing type', () => {
    const result = validateSubproblem({
      detail: 'No type field',
    });
    expect(result.success).toBe(false);
  });

  it('rejects instance with whitespace', () => {
    // RFC 3986 disallows raw whitespace in URI-
    // references — it must be percent-encoded.
    const result = validateSubproblem({
      type: 'urn:ietf:params:acme:error:malformed',
      instance: 'not a url',
    });
    expect(result.success).toBe(false);
  });

  it('rejects instance with control characters', () => {
    // RFC 3986 disallows raw control characters —
    // must be percent-encoded.
    const nul = validateSubproblem({
      type: 'urn:ietf:params:acme:error:malformed',
      instance: '\u0001',
    });
    expect(nul.success).toBe(false);
    const newline = validateSubproblem({
      type: 'urn:ietf:params:acme:error:malformed',
      instance: 'a\nb',
    });
    expect(newline.success).toBe(false);
  });

  it('accepts relative URI-reference instance', () => {
    // RFC 7807 §3.1 permits relative URI-references.
    const result = validateSubproblem({
      type: 'urn:ietf:params:acme:error:malformed',
      instance: '/acme/acct/1',
    });
    expect(result.success).toBe(true);
  });
});

describe('validateProblem', () => {
  it('accepts a problem without subproblems', () => {
    const result = validateProblem({
      type: 'urn:ietf:params:acme:error:unauthorized',
      detail: 'Account not authorized',
      status: 403,
    });
    expect(result.success).toBe(true);
  });

  it('accepts a problem with subproblems', () => {
    const result = validateProblem({
      type: 'urn:ietf:params:acme:error:compound',
      detail: 'Multiple errors',
      status: 400,
      subproblems: [
        {
          type: 'urn:ietf:params:acme:error:rejectedIdentifier',
          detail: 'Rejected',
          identifier: { type: 'dns', value: 'bad.example' },
        },
      ],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.subproblems).toHaveLength(1);
    }
  });

  it('accepts non-ACME error URNs', () => {
    const result = validateProblem({
      type: 'urn:custom:error:something',
      detail: 'Server-defined error',
    });
    expect(result.success).toBe(true);
  });

  it('rejects instance with whitespace', () => {
    // RFC 3986 disallows raw whitespace in URI-
    // references — it must be percent-encoded.
    const result = validateProblem({
      type: 'urn:ietf:params:acme:error:malformed',
      instance: 'not a url',
    });
    expect(result.success).toBe(false);
  });

  it('rejects instance with control characters', () => {
    // RFC 3986 disallows raw control characters —
    // must be percent-encoded.
    const nul = validateProblem({
      type: 'urn:ietf:params:acme:error:malformed',
      instance: '\u0001',
    });
    expect(nul.success).toBe(false);
    const newline = validateProblem({
      type: 'urn:ietf:params:acme:error:malformed',
      instance: 'a\nb',
    });
    expect(newline.success).toBe(false);
  });

  it('accepts urn: instance (absolute URI)', () => {
    const result = validateProblem({
      type: 'urn:ietf:params:acme:error:malformed',
      instance: 'urn:uuid:1234',
    });
    expect(result.success).toBe(true);
  });

  it('accepts relative URI-reference instance', () => {
    // RFC 7807 §3.1 permits relative URI-references.
    const result = validateProblem({
      type: 'urn:ietf:params:acme:error:malformed',
      instance: '/acme/acct/1',
    });
    expect(result.success).toBe(true);
  });

  it('preserves unknown fields', () => {
    const result = validateProblem({
      type: 'urn:ietf:params:acme:error:malformed',
      futureField: 'some-value',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as Record<string, unknown>)
          .futureField,
      ).toBe('some-value');
    }
  });
});
