// ACME schema test utilities (RFC 8555)

import type * as v from 'valibot';

/**
 * The JSON value `null` as a typed constant, for
 * validator tests that need to assert rejection of a
 * parsed-JSON `null`.
 *
 * @remarks
 * The repo-wide `unicorn/no-null` rule forbids `null`
 * literals. Schema validators, however, must be tested
 * against the exact value an HTTP handler sees after
 * `JSON.parse` — that includes `null`. Routing every
 * such test through this constant keeps the lint rule
 * active everywhere else and documents intent.
 */
// eslint-disable-next-line unicorn/no-null
export const jsonNull: unknown = null;

/**
 * Recursively strip index signatures from a type,
 * distributing over unions and descending into
 * arrays and object properties.
 *
 * @remarks
 * Preserves `readonly` on arrays: `readonly T[]`
 * stays readonly, `T[]` stays mutable. Branded
 * strings (e.g. `Base64url = string & { [brand]: void }`)
 * short-circuit via the `extends string` case — the
 * mapped rewrite would otherwise strip the primitive
 * side of the intersection.
 *
 * Typed arrays (`Uint8Array`, `Uint16Array`, …)
 * normalise to their default-parameter form so schema
 * outputs like `v.instance(Uint8Array)` — which infer
 * `Uint8Array<ArrayBuffer>` via the constructor
 * overload — match hand-written `Uint8Array`
 * (`Uint8Array<ArrayBufferLike>` by default).
 *
 * Built-in object instances that the mapped-type
 * descent would otherwise dissolve into a key-of map
 * (`Date` and friends) short-circuit on identity. Add
 * a branch per consumer the schema layer introduces;
 * the alphabetical ordering below makes new entries
 * obvious.
 */
export type DeepStripIndex<T> =
  T extends string ? T :
    T extends Date ? Date :
      T extends Uint8Array ? Uint8Array :
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
