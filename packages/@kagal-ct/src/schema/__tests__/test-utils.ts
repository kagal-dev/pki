// Compile-time test utilities for schema ↔ type
// conformance checks.

import type * as v from 'valibot';

/**
 * Recursively strip index signatures from a type,
 * distributing over unions and descending into
 * arrays and object properties.
 *
 * @remarks
 * Preserves `readonly` on arrays: `readonly T[]`
 * stays readonly, `T[]` stays mutable.
 */
export type DeepStripIndex<T> =
  T extends readonly (infer U)[] ?
    T extends unknown[] ?
      DeepStripIndex<U>[] :
      readonly DeepStripIndex<U>[] :
    T extends object ?
      {
        [K in keyof T as string extends K ?
          never :
          number extends K ? never :
            K]: DeepStripIndex<T[K]>
      } :
      T;

/** Schema output with index signatures stripped. */
export type SchemaOutput<
  T extends v.BaseSchema<
    unknown, unknown, v.BaseIssue<unknown>
  >,
> = DeepStripIndex<v.InferOutput<T>>;
