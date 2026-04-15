// Object member assertions.

/**
 * Assert that each named member of `object` is a
 * non-empty string.
 *
 * @param object - the object to verify.
 * @param members - the member names that must be
 *   present and non-empty strings.
 * @throws TypeError if any named member is absent,
 *   is not a string, or is the empty string.
 *
 * @example
 * ```typescript
 * function canonicaliseEC(jwk: ECJWK) {
 *   mustMembers(jwk, 'crv', 'x', 'y');
 *   return { crv: jwk.crv, x: jwk.x, y: jwk.y };
 * }
 * ```
 */
export function mustMembers<K extends string>(
  object: object,
  ...members: K[]
): asserts object is Record<K, string> {
  const record = object as Record<string, unknown>;
  for (const member of members) {
    if (
      typeof record[member] !== 'string' ||
      record[member] === ''
    ) {
      throw new TypeError(
        `member "${member}" must be a non-empty string`,
      );
    }
  }
}
