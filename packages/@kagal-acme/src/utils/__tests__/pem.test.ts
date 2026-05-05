// PEM encode/decode tests (RFC 7468).

import { describe, expect, it } from 'vitest';

import { decodePEM, encodePEM } from '..';
import { ProblemError } from '../../error';
import { asPEM } from '../../types';

const MALFORMED_URN = 'urn:ietf:params:acme:error:malformed';

function expectMalformed(fn: () => unknown, detailRegex: RegExp): void {
  try {
    fn();
    expect.fail('expected ProblemError to be thrown');
  } catch (error) {
    expect(error).toBeInstanceOf(ProblemError);
    const problem = (error as ProblemError).problem;
    expect(problem.type).toBe(MALFORMED_URN);
    expect(problem.status).toBe(400);
    expect(problem.detail).toMatch(detailRegex);
  }
}

describe('encodePEM', () => {
  it('round-trips arbitrary bytes through decodePEM', () => {
    const bytes = new Uint8Array([0, 1, 2, 3, 4, 5, 250, 251, 252]);
    const pem = encodePEM(bytes, 'CERTIFICATE');
    const decoded = decodePEM(pem, 'CERTIFICATE');
    expect([...decoded]).toEqual([...bytes]);
  });

  it('produces a PEM block with the given label', () => {
    const pem = encodePEM(new Uint8Array([1, 2, 3]), 'PUBLIC KEY');
    expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(pem).toMatch(/-----END PUBLIC KEY-----\s*$/);
  });
});

describe('decodePEM', () => {
  it('throws malformed on a PEM input with zero blocks', () => {
    const empty = asPEM('');
    expectMalformed(
      () => decodePEM(empty, 'CERTIFICATE'),
      /no blocks/,
    );
  });

  it('throws malformed on a concatenated chain (multiple blocks)', () => {
    const first = encodePEM(new Uint8Array([1]), 'CERTIFICATE');
    const second = encodePEM(new Uint8Array([2]), 'CERTIFICATE');
    const chain = asPEM(`${first}${second}`);
    expectMalformed(
      () => decodePEM(chain, 'CERTIFICATE'),
      /2 blocks/,
    );
  });

  it('throws malformed on a label mismatch', () => {
    const pem = encodePEM(new Uint8Array([1, 2]), 'CERTIFICATE');
    expectMalformed(
      () => decodePEM(pem, 'CERTIFICATE REQUEST'),
      /label mismatch/,
    );
  });

  it('returns a Uint8Array backed by a non-shared ArrayBuffer', () => {
    const pem = encodePEM(new Uint8Array([9, 8, 7]), 'PUBLIC KEY');
    const bytes = decodePEM(pem, 'PUBLIC KEY');
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.buffer).toBeInstanceOf(ArrayBuffer);
  });
});
