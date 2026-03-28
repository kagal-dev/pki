// Type-narrowing utilities

/**
 * Narrows `value` to `T` if it belongs to `set`,
 * otherwise `undefined`.
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
