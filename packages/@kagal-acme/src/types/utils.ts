// Type-narrowing utilities

/**
 * Narrows `value` to `T` if it belongs to `set`,
 * otherwise `undefined`.
 *
 * @remarks
 * Use at trust boundaries to convert raw input strings
 * into a typed union. Pairs with the `*Statuses` /
 * `*Types` `ReadonlySet` constants exported from
 * `@kagal/acme/types` (e.g. {@link OrderStatuses},
 * {@link IdentifierTypes}, {@link ErrorTypes}): the
 * result is a fully-typed status / type / etc., or
 * `undefined` if the input is not a valid member.
 *
 * Safer than `set.has(x as T) ? x as T : undefined`
 * because the narrowing flows through inference rather
 * than the caller asserting it — there is no `as T`
 * cast at the call site to drift if the underlying
 * tuple changes.
 *
 * @param set - ReadonlySet to check membership against
 * @param value - string to narrow
 * @returns the value as `T`, or `undefined`
 *
 * @example
 * ```typescript
 * const status = narrow(OrderStatuses, raw);
 * //    ^? OrderStatus | undefined
 * ```
 */
export function narrow<T extends string>(
  set: ReadonlySet<T>,
  value: string,
): T | undefined {
  return set.has(value as T) ? value as T : undefined;
}
