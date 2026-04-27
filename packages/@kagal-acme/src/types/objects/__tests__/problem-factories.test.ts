// newProblem / newSubproblem data factory tests
// (RFC 7807, RFC 8555 §6.7 / §6.7.1)
// cspell:words NXDOMAIN

import { describe, expect, it } from 'vitest';

import {
  newProblem,
  newSubproblem,
  type Subproblem,
} from '../problem';

describe('newProblem', () => {
  it('derives status from the URN table', () => {
    expect(newProblem('urn:ietf:params:acme:error:malformed')).toEqual({
      type: 'urn:ietf:params:acme:error:malformed',
      status: 400,
    });
    expect(newProblem('urn:ietf:params:acme:error:rateLimited')).toEqual({
      type: 'urn:ietf:params:acme:error:rateLimited',
      status: 429,
    });
    expect(newProblem('urn:ietf:params:acme:error:serverInternal')).toEqual({
      type: 'urn:ietf:params:acme:error:serverInternal',
      status: 500,
    });
  });

  it('honours options.status, falling back to the table', () => {
    // Boulder reuses malformed with 404 / 405.
    expect(
      newProblem('urn:ietf:params:acme:error:malformed', 'No such order', {
        status: 404,
      }).status,
    ).toBe(404);
    expect(
      newProblem('urn:ietf:params:acme:error:malformed').status,
    ).toBe(400);
  });

  it('includes detail when provided, omits when undefined', () => {
    const withDetail = newProblem(
      'urn:ietf:params:acme:error:malformed',
      'schema validation failed',
    );
    expect(withDetail.detail).toBe('schema validation failed');

    const withoutDetail = newProblem('urn:ietf:params:acme:error:malformed');
    expect(withoutDetail).not.toHaveProperty('detail');
  });

  it('attaches subproblems when provided (any top-level URN)', () => {
    // RFC 8555 §6.7.1 worked example uses `malformed` with subproblems.
    const subproblems: Subproblem[] = [
      {
        type: 'urn:ietf:params:acme:error:rejectedIdentifier',
        identifier: { type: 'dns', value: 'bad.example' },
      },
    ];
    const problem = newProblem(
      'urn:ietf:params:acme:error:malformed',
      'Some identifiers were rejected',
      { status: 403, subproblems },
    );
    expect(problem).toEqual({
      type: 'urn:ietf:params:acme:error:malformed',
      status: 403,
      detail: 'Some identifiers were rejected',
      subproblems,
    });
  });

  it('omits subproblems key when option not provided', () => {
    const problem = newProblem('urn:ietf:params:acme:error:malformed');
    expect(problem).not.toHaveProperty('subproblems');
  });

  it('passes subproblems by reference (caller owns hermeticity)', () => {
    const subproblems: Subproblem[] = [
      {
        type: 'urn:ietf:params:acme:error:rejectedIdentifier',
        identifier: { type: 'dns', value: 'first.example' },
      },
    ];
    const problem = newProblem(
      'urn:ietf:params:acme:error:compound',
      undefined,
      { subproblems },
    );
    // Same reference — newProblem does not deep-copy.
    // Hermeticity is the caller's responsibility.
    expect(problem.subproblems).toBe(subproblems);

    // Mutation of the source array IS visible on the
    // returned Problem — this is the documented contract.
    subproblems.push({
      type: 'urn:ietf:params:acme:error:caa',
      identifier: { type: 'dns', value: 'second.example' },
    });
    expect(problem.subproblems).toHaveLength(2);
  });

  it('returns Problem suitable for application/problem+json wire form', () => {
    const problem = newProblem(
      'urn:ietf:params:acme:error:rejectedIdentifier',
      'No can do',
    );
    // eslint-disable-next-line unicorn/prefer-structured-clone -- testing JSON wire round-trip, not cloning
    expect(JSON.parse(JSON.stringify(problem))).toEqual(problem);
  });
});

describe('newSubproblem', () => {
  it('builds with type only', () => {
    expect(newSubproblem('urn:ietf:params:acme:error:dns')).toEqual({
      type: 'urn:ietf:params:acme:error:dns',
    });
  });

  it('includes identifier when provided', () => {
    expect(
      newSubproblem('urn:ietf:params:acme:error:caa', {
        type: 'dns',
        value: 'caa.example',
      }),
    ).toEqual({
      type: 'urn:ietf:params:acme:error:caa',
      identifier: { type: 'dns', value: 'caa.example' },
    });
  });

  it('includes detail when provided', () => {
    expect(
      newSubproblem(
        'urn:ietf:params:acme:error:dns',
        { type: 'dns', value: 'bad.example' },
        'NXDOMAIN',
      ),
    ).toEqual({
      type: 'urn:ietf:params:acme:error:dns',
      identifier: { type: 'dns', value: 'bad.example' },
      detail: 'NXDOMAIN',
    });
  });

  it('accepts detail without identifier (e.g. aggregating non-identifier-bound failures)', () => {
    expect(
      newSubproblem('urn:ietf:params:acme:error:dns', undefined, 'NXDOMAIN'),
    ).toEqual({
      type: 'urn:ietf:params:acme:error:dns',
      detail: 'NXDOMAIN',
    });
  });

  it('omits identifier and detail keys when not provided', () => {
    const subproblem = newSubproblem('urn:ietf:params:acme:error:dns');
    expect(subproblem).not.toHaveProperty('identifier');
    expect(subproblem).not.toHaveProperty('detail');
  });

  it('does not set status, title, or instance (rarer fields require a literal)', () => {
    const subproblem = newSubproblem(
      'urn:ietf:params:acme:error:dns',
      { type: 'dns', value: 'bad.example' },
      'NXDOMAIN',
    );
    expect(subproblem).not.toHaveProperty('status');
    expect(subproblem).not.toHaveProperty('title');
    expect(subproblem).not.toHaveProperty('instance');
  });
});

describe('barrel exports', () => {
  it('re-exports newProblem and newSubproblem from /types', async () => {
    const barrel = await import('../..');
    expect(barrel.newProblem).toBe(newProblem);
    expect(barrel.newSubproblem).toBe(newSubproblem);
  });
});
