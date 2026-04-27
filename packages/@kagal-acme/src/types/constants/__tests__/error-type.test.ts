// errorStatus table contents
// (RFC 8555 §6.7, RFC 9773 §7.4, Boulder's problems package)

import { describe, expect, it } from 'vitest';

import { errorStatus, errorTypes } from '../error-type';

describe('errorStatus', () => {
  it('has an entry for every URN in errorTypes', () => {
    // Compile-time exhaustiveness via Record<ErrorType, number>
    // is the primary guarantee; this is the runtime backstop.
    for (const urn of errorTypes) {
      expect(errorStatus).toHaveProperty(urn);
    }
    expect(Object.keys(errorStatus)).toHaveLength(errorTypes.length);
  });

  it('locks the RFC 9773 §7.4 MUST: alreadyReplaced is 409', () => {
    expect(
      errorStatus['urn:ietf:params:acme:error:alreadyReplaced'],
    ).toBe(409);
  });

  it('matches Boulder defaults for the dominant URNs', () => {
    expect(
      errorStatus['urn:ietf:params:acme:error:malformed'],
    ).toBe(400);
    expect(
      errorStatus['urn:ietf:params:acme:error:badNonce'],
    ).toBe(400);
    expect(
      errorStatus['urn:ietf:params:acme:error:unauthorized'],
    ).toBe(403);
    expect(
      errorStatus['urn:ietf:params:acme:error:caa'],
    ).toBe(403);
    expect(
      errorStatus['urn:ietf:params:acme:error:rateLimited'],
    ).toBe(429);
    expect(
      errorStatus['urn:ietf:params:acme:error:serverInternal'],
    ).toBe(500);
  });
});
