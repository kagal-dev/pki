// Tests for object member assertions.

import { describe, expect, it } from 'vitest';

import { mustMembers } from '../assert';

describe('mustMembers', () => {
  it('passes when all named members are non-empty strings', () => {
    expect(() =>
      mustMembers({ a: 'x', b: 'y' }, 'a', 'b'),
    ).not.toThrow();
  });

  it('throws TypeError when a member is absent', () => {
    expect(() =>
      mustMembers({ a: 'x' } as object, 'a', 'b'),
    ).toThrow(TypeError);
    expect(() =>
      mustMembers({ a: 'x' } as object, 'a', 'b'),
    ).toThrow(/member "b" must be a non-empty string/);
  });

  it('throws TypeError when a member is not a string', () => {
    expect(() =>
      mustMembers({ a: 'x', b: 42 } as object, 'a', 'b'),
    ).toThrow(TypeError);
  });

  it('throws TypeError when a member is the empty string', () => {
    expect(() =>
      mustMembers({ a: 'x', b: '' }, 'a', 'b'),
    ).toThrow(TypeError);
  });

  it('treats an empty member list as a no-op', () => {
    expect(() => mustMembers({})).not.toThrow();
  });
});
