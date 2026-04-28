// ProblemError tests (RFC 7807, RFC 8555 §6.7)

// cspell:words NXDOMAIN

import { describe, expect, it } from 'vitest';

import type { Problem, Subproblem } from '../../types/objects/problem';
import { ProblemError, SubproblemError } from '../problem';

describe('ProblemError', () => {
  it('wraps a Problem and exposes it on .problem', () => {
    const problem: Problem = {
      type: 'urn:ietf:params:acme:error:malformed',
      detail: 'Flattened JWS failed schema validation',
      status: 400,
    };
    const error = new ProblemError(problem);
    expect(error.problem).toBe(problem);
  });

  it('is an Error and a ProblemError', () => {
    const error = new ProblemError({
      type: 'urn:ietf:params:acme:error:malformed',
    });
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(ProblemError);
    expect(error.name).toBe('ProblemError');
  });

  it('uses problem.detail as the Error message', () => {
    const error = new ProblemError({
      type: 'urn:ietf:params:acme:error:unauthorized',
      title: 'Unauthorized',
      detail: 'JWS signature verification failed',
    });
    expect(error.message).toBe('JWS signature verification failed');
  });

  it('falls back to problem.title when detail is absent', () => {
    const error = new ProblemError({
      type: 'urn:ietf:params:acme:error:unauthorized',
      title: 'Unauthorized',
    });
    expect(error.message).toBe('Unauthorized');
  });

  it('falls back to problem.type when detail and title are absent', () => {
    const error = new ProblemError({
      type: 'urn:ietf:params:acme:error:malformed',
    });
    expect(error.message).toBe('urn:ietf:params:acme:error:malformed');
  });

  it('propagates options.cause to Error.cause', () => {
    const cause = new SyntaxError('Unexpected token');
    const error = new ProblemError(
      {
        type: 'urn:ietf:params:acme:error:malformed',
        detail: 'JWS payload is not valid JSON',
      },
      { cause },
    );
    expect(error.cause).toBe(cause);
  });

  it('preserves status and subproblems with per-identifier context', () => {
    const problem: Problem = {
      type: 'urn:ietf:params:acme:error:compound',
      detail: 'Multiple identifier failures',
      status: 400,
      subproblems: [
        {
          type: 'urn:ietf:params:acme:error:rejectedIdentifier',
          identifier: { type: 'dns', value: 'bad.example' },
        },
      ],
    };
    const error = new ProblemError(problem);
    expect(error.problem.status).toBe(400);
    expect(error.problem.subproblems).toHaveLength(1);
    expect(error.problem.subproblems?.[0].identifier).toEqual({
      type: 'dns',
      value: 'bad.example',
    });
  });

  it('serialises problem to the application/problem+json wire shape', () => {
    const problem: Problem = {
      type: 'urn:ietf:params:acme:error:compound',
      title: 'Multiple errors',
      detail: 'Multiple identifier failures',
      status: 400,
      subproblems: [
        {
          type: 'urn:ietf:params:acme:error:rejectedIdentifier',
          identifier: { type: 'dns', value: 'bad.example' },
        },
      ],
    };
    const error = new ProblemError(problem);
    // eslint-disable-next-line unicorn/prefer-structured-clone -- testing JSON wire round-trip, not cloning
    expect(JSON.parse(JSON.stringify(error.problem))).toEqual(problem);
  });

  it('preserves the RFC 7807 instance field on the wire', () => {
    const problem: Problem = {
      type: 'urn:ietf:params:acme:error:malformed',
      detail: 'JWS payload is not valid JSON',
      instance: 'https://acme.example/orders/42',
      status: 400,
    };
    const error = new ProblemError(problem);
    expect(error.problem.instance).toBe(
      'https://acme.example/orders/42',
    );
    // eslint-disable-next-line unicorn/prefer-structured-clone -- testing JSON wire round-trip, not cloning
    expect(JSON.parse(JSON.stringify(error.problem))).toEqual(problem);
  });

  it('is catchable as ProblemError via instanceof', () => {
    const thrown = ((): unknown => {
      try {
        throw new ProblemError({
          type: 'urn:ietf:params:acme:error:unauthorized',
          status: 401,
        });
      } catch (error) {
        return error;
      }
    })();
    expect(thrown).toBeInstanceOf(ProblemError);
    if (thrown instanceof ProblemError) {
      expect(thrown.problem.status).toBe(401);
    }
  });
});

describe('ProblemError factories', () => {
  it('of() derives status from the URN', () => {
    const error = ProblemError.of(
      'urn:ietf:params:acme:error:rateLimited',
      'Slow down',
    );
    expect(error.problem.type).toBe('urn:ietf:params:acme:error:rateLimited');
    expect(error.problem.status).toBe(429);
    expect(error.problem.detail).toBe('Slow down');
  });

  it('of() omits detail when undefined', () => {
    const error = ProblemError.of('urn:ietf:params:acme:error:malformed');
    expect(error.problem).toEqual({
      type: 'urn:ietf:params:acme:error:malformed',
      status: 400,
    });
  });

  it('of() forwards cause to Error.cause', () => {
    const cause = new TypeError('boom');
    const error = ProblemError.of(
      'urn:ietf:params:acme:error:malformed',
      'bad input',
      { cause },
    );
    expect(error.cause).toBe(cause);
  });

  it('of() honours options.status, falling back to the table', () => {
    // Boulder reuses the malformed URN with 404 / 405.
    const notFound = ProblemError.of(
      'urn:ietf:params:acme:error:malformed',
      'No such order',
      { status: 404 },
    );
    expect(notFound.problem.status).toBe(404);

    const fallback = ProblemError.of('urn:ietf:params:acme:error:malformed');
    expect(fallback.problem.status).toBe(400);
  });

  it('factories honour options.status', () => {
    const error = ProblemError.malformed('No such order', { status: 404 });
    expect(error.problem.status).toBe(404);
  });

  it('compound() honours options.status', () => {
    const error = ProblemError.compound([], 'aggregate', { status: 422 });
    expect(error.problem.status).toBe(422);
  });

  it('malformed() returns a 400 malformed problem', () => {
    const error = ProblemError.malformed('schema validation failed');
    expect(error.problem.type).toBe('urn:ietf:params:acme:error:malformed');
    expect(error.problem.status).toBe(400);
    expect(error.problem.detail).toBe('schema validation failed');
  });

  it('unauthorized() returns a 403 unauthorized problem', () => {
    const error = ProblemError.unauthorized('signature failed');
    expect(error.problem.type).toBe('urn:ietf:params:acme:error:unauthorized');
    expect(error.problem.status).toBe(403);
  });

  it('serverInternal() returns a 500 problem', () => {
    const error = ProblemError.serverInternal();
    expect(error.problem.type).toBe(
      'urn:ietf:params:acme:error:serverInternal',
    );
    expect(error.problem.status).toBe(500);
    expect(error.problem.detail).toBeUndefined();
  });

  it('compound() aggregates subproblems with status 400', () => {
    const subproblems: Subproblem[] = [
      {
        type: 'urn:ietf:params:acme:error:rejectedIdentifier',
        identifier: { type: 'dns', value: 'bad.example' },
      },
      {
        type: 'urn:ietf:params:acme:error:caa',
        identifier: { type: 'dns', value: 'caa.example' },
      },
    ];
    const error = ProblemError.compound(
      subproblems,
      'Two identifiers failed',
    );
    expect(error.problem.type).toBe('urn:ietf:params:acme:error:compound');
    expect(error.problem.status).toBe(400);
    expect(error.problem.subproblems).toHaveLength(2);
    expect(error.problem.detail).toBe('Two identifiers failed');
  });

  it('factories produce instances of ProblemError', () => {
    expect(ProblemError.malformed()).toBeInstanceOf(ProblemError);
    expect(ProblemError.unauthorized()).toBeInstanceOf(ProblemError);
    expect(ProblemError.serverInternal()).toBeInstanceOf(ProblemError);
    expect(ProblemError.compound([])).toBeInstanceOf(ProblemError);
  });

  it('exports ProblemError and SubproblemError from the barrel', async () => {
    const barrel = await import('../index');
    expect(barrel.ProblemError).toBe(ProblemError);
    expect(barrel.SubproblemError).toBe(SubproblemError);
    const error = barrel.ProblemError.malformed('barrel-imported');
    expect(error).toBeInstanceOf(ProblemError);
    expect(error.problem.status).toBe(400);
  });

  it('compound() accepts SubproblemError instances and unwraps them', () => {
    const errors = [
      SubproblemError.rejectedIdentifier(
        { type: 'dns', value: 'first.example' },
        'rejected',
      ),
      SubproblemError.caa(
        { type: 'dns', value: 'second.example' },
        'CAA forbids',
      ),
    ];
    const error = ProblemError.compound(errors, 'two failures');
    expect(error.problem.subproblems).toHaveLength(2);
    expect(error.problem.subproblems?.[0]).toEqual({
      type: 'urn:ietf:params:acme:error:rejectedIdentifier',
      identifier: { type: 'dns', value: 'first.example' },
      detail: 'rejected',
    });
    expect(error.problem.subproblems?.[1]).toEqual({
      type: 'urn:ietf:params:acme:error:caa',
      identifier: { type: 'dns', value: 'second.example' },
      detail: 'CAA forbids',
    });
  });

  it('compound() drops Error.cause from SubproblemError entries on the wire', () => {
    const cause = new Error('upstream DNS lookup failed');
    const subproblemError = SubproblemError.of(
      'urn:ietf:params:acme:error:dns',
      { type: 'dns', value: 'bad.example' },
      'NXDOMAIN',
      { cause },
    );
    expect(subproblemError.cause).toBe(cause);
    const error = ProblemError.compound([subproblemError], 'one failure');
    // eslint-disable-next-line unicorn/prefer-structured-clone -- testing JSON wire round-trip, not cloning
    const wire = JSON.parse(JSON.stringify(error.problem)) as Problem;
    expect(wire.subproblems).toHaveLength(1);
    expect(wire.subproblems?.[0]).toEqual({
      type: 'urn:ietf:params:acme:error:dns',
      identifier: { type: 'dns', value: 'bad.example' },
      detail: 'NXDOMAIN',
    });
    expect(wire.subproblems?.[0]).not.toHaveProperty('cause');
  });

  it('compound() accepts a mixed array of Subproblem and SubproblemError', () => {
    const subproblem: Subproblem = {
      type: 'urn:ietf:params:acme:error:dns',
      identifier: { type: 'dns', value: 'plain.example' },
    };
    const subproblemError = SubproblemError.rejectedIdentifier(
      { type: 'dns', value: 'wrapped.example' },
    );
    const error = ProblemError.compound(
      [subproblem, subproblemError],
      'mixed',
    );
    expect(error.problem.subproblems).toHaveLength(2);
    expect(error.problem.subproblems?.[0].type).toBe(
      'urn:ietf:params:acme:error:dns',
    );
    expect(error.problem.subproblems?.[1].type).toBe(
      'urn:ietf:params:acme:error:rejectedIdentifier',
    );
  });

  it('compound() deep-copies subproblems so caller mutation does not leak', () => {
    const subproblems: Subproblem[] = [
      {
        type: 'urn:ietf:params:acme:error:rejectedIdentifier',
        identifier: { type: 'dns', value: 'first.example' },
      },
    ];
    const error = ProblemError.compound(subproblems, 'one failure');

    // array-level mutation
    subproblems.push({
      type: 'urn:ietf:params:acme:error:caa',
      identifier: { type: 'dns', value: 'second.example' },
    });
    // entry-level mutation
    subproblems[0].identifier = {
      type: 'dns',
      value: 'rewritten.example',
    };
    if (subproblems[0].identifier) {
      subproblems[0].identifier.value = 'mutated-deeply.example';
    }

    expect(error.problem.subproblems).toHaveLength(1);
    expect(error.problem.subproblems?.[0].identifier).toEqual({
      type: 'dns',
      value: 'first.example',
    });
  });
});

describe('SubproblemError', () => {
  it('wraps a Subproblem and exposes it on .subproblem', () => {
    const subproblem: Subproblem = {
      type: 'urn:ietf:params:acme:error:rejectedIdentifier',
      identifier: { type: 'dns', value: 'bad.example' },
      detail: 'rejected',
    };
    const error = new SubproblemError(subproblem);
    expect(error.subproblem).toBe(subproblem);
  });

  it('is an Error and a SubproblemError', () => {
    const error = new SubproblemError({
      type: 'urn:ietf:params:acme:error:caa',
    });
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(SubproblemError);
    expect(error.name).toBe('SubproblemError');
  });

  it('uses subproblem.detail as the Error message', () => {
    const error = new SubproblemError({
      type: 'urn:ietf:params:acme:error:caa',
      detail: 'CAA record forbids issuance',
    });
    expect(error.message).toBe('CAA record forbids issuance');
  });

  it('falls back to subproblem.title when detail is absent', () => {
    const error = new SubproblemError({
      type: 'urn:ietf:params:acme:error:caa',
      title: 'CAA',
    });
    expect(error.message).toBe('CAA');
  });

  it('falls back to subproblem.type when detail and title are absent', () => {
    const error = new SubproblemError({
      type: 'urn:ietf:params:acme:error:caa',
    });
    expect(error.message).toBe('urn:ietf:params:acme:error:caa');
  });

  it('propagates options.cause to Error.cause', () => {
    const cause = new Error('upstream DNS lookup failed');
    const error = new SubproblemError(
      {
        type: 'urn:ietf:params:acme:error:dns',
        identifier: { type: 'dns', value: 'bad.example' },
      },
      { cause },
    );
    expect(error.cause).toBe(cause);
  });

  it('is catchable as SubproblemError via instanceof', () => {
    const thrown = ((): unknown => {
      try {
        throw SubproblemError.rejectedIdentifier(
          { type: 'dns', value: 'bad.example' },
        );
      } catch (error) {
        return error;
      }
    })();
    expect(thrown).toBeInstanceOf(SubproblemError);
    if (thrown instanceof SubproblemError) {
      expect(thrown.subproblem.identifier).toEqual({
        type: 'dns',
        value: 'bad.example',
      });
    }
  });
});

describe('SubproblemError factories', () => {
  it('of() builds with type only', () => {
    const error = SubproblemError.of('urn:ietf:params:acme:error:dns');
    expect(error.subproblem).toEqual({
      type: 'urn:ietf:params:acme:error:dns',
    });
  });

  it('of() includes identifier and detail when provided', () => {
    const error = SubproblemError.of(
      'urn:ietf:params:acme:error:dns',
      { type: 'dns', value: 'bad.example' },
      'NXDOMAIN',
    );
    expect(error.subproblem).toEqual({
      type: 'urn:ietf:params:acme:error:dns',
      identifier: { type: 'dns', value: 'bad.example' },
      detail: 'NXDOMAIN',
    });
  });

  it('of() forwards cause to Error.cause', () => {
    const cause = new TypeError('boom');
    const error = SubproblemError.of(
      'urn:ietf:params:acme:error:dns',
      undefined,
      undefined,
      { cause },
    );
    expect(error.cause).toBe(cause);
  });

  it('rejectedIdentifier() carries the URN and identifier', () => {
    const error = SubproblemError.rejectedIdentifier(
      { type: 'dns', value: 'bad.example' },
      'not allowed',
    );
    expect(error.subproblem.type).toBe(
      'urn:ietf:params:acme:error:rejectedIdentifier',
    );
    expect(error.subproblem.identifier).toEqual({
      type: 'dns',
      value: 'bad.example',
    });
    expect(error.subproblem.detail).toBe('not allowed');
  });

  it('caa() carries the URN and identifier', () => {
    const error = SubproblemError.caa(
      { type: 'dns', value: 'caa.example' },
    );
    expect(error.subproblem.type).toBe('urn:ietf:params:acme:error:caa');
    expect(error.subproblem.identifier).toEqual({
      type: 'dns',
      value: 'caa.example',
    });
    expect(error.subproblem.detail).toBeUndefined();
  });

  it('factories produce instances of SubproblemError', () => {
    const identifier = { type: 'dns', value: 'x.example' } as const;
    expect(SubproblemError.of('urn:ietf:params:acme:error:dns')).toBeInstanceOf(
      SubproblemError,
    );
    expect(SubproblemError.rejectedIdentifier(identifier)).toBeInstanceOf(
      SubproblemError,
    );
    expect(SubproblemError.caa(identifier)).toBeInstanceOf(SubproblemError);
  });
});
