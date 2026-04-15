// Brand + signature assertions for @kagal/acme/types
// encoding helpers. Compile-time only — these
// `expectTypeOf` calls produce no runtime output; the
// file is type-checked via tsconfig.tests.json but
// never executed by vitest (not a `*.test.ts` file).

import type * as v from 'valibot';
import { expectTypeOf } from 'vitest';

import {
  asBase64url,
  asPEM,
  type Base64url,
  type PEM,
} from '../encoding';

import {
  Base64urlOrEmptySchema,
  Base64urlSchema,
  PEMSchema,
  validateBase64url,
  validateBase64urlOrEmpty,
  validatePEM,
  type ValidationResult,
} from '../../schema';

import {
  encodeBase64url,
  getRandom,
  jwkThumbprint,
} from '../../utils';

// -- brand asymmetry --

// A branded string is still a string: reads, concat,
// JSON.stringify, storage writes all work transparently.
expectTypeOf<Base64url>().toExtend<string>();
expectTypeOf<PEM>().toExtend<string>();

// A plain string is NOT a branded value: writes require
// the brand, preventing silent mix-ups at call sites.
expectTypeOf<string>().not.toExtend<Base64url>();
expectTypeOf<string>().not.toExtend<PEM>();

// -- brand disjointness --

// Base64url and PEM do not widen into each other. A
// `getChain()` result cannot be passed where a JWS
// signature is expected, and vice versa.
expectTypeOf<Base64url>().not.toExtend<PEM>();
expectTypeOf<PEM>().not.toExtend<Base64url>();

// -- accessor signatures --

expectTypeOf<
  ReturnType<typeof asBase64url>
>().toEqualTypeOf<Base64url>();
expectTypeOf<
  ReturnType<typeof asPEM>
>().toEqualTypeOf<PEM>();

// Accessor inputs are plain `string` — the whole point
// is to bridge raw strings into the branded world. If
// these ever widen to `unknown`, the accessor becomes a
// lie (it would claim any value is a Base64url).
expectTypeOf<
  Parameters<typeof asBase64url>[0]
>().toEqualTypeOf<string>();
expectTypeOf<
  Parameters<typeof asPEM>[0]
>().toEqualTypeOf<string>();

// -- producer return types --

// If any of these widen back to `string`, the entire
// branding effort silently reverts for that producer.
expectTypeOf<
  ReturnType<typeof encodeBase64url>
>().toEqualTypeOf<Base64url>();
expectTypeOf<
  ReturnType<typeof getRandom>
>().toEqualTypeOf<Base64url>();
expectTypeOf<
  Awaited<ReturnType<typeof jwkThumbprint>>
>().toEqualTypeOf<Base64url>();

// -- validator outputs --

expectTypeOf<
  ReturnType<typeof validateBase64url>
>().toEqualTypeOf<ValidationResult<Base64url>>();

// `validateBase64urlOrEmpty` returns `'' | Base64url`:
// non-empty matches are branded, the empty case stays
// a literal empty string (the brand's non-empty regex
// rejects `''`).
expectTypeOf<
  ReturnType<typeof validateBase64urlOrEmpty>
>().toEqualTypeOf<ValidationResult<'' | Base64url>>();

expectTypeOf<
  ReturnType<typeof validatePEM>
>().toEqualTypeOf<ValidationResult<PEM>>();

// -- schema output --

// `Base64urlSchema` must transform its output to the
// brand. If the trailing `v.transform` is removed,
// `InferOutput` collapses back to `string` and this
// fires.
expectTypeOf<
  v.InferOutput<typeof Base64urlSchema>
>().toEqualTypeOf<Base64url>();

expectTypeOf<
  v.InferOutput<typeof Base64urlOrEmptySchema>
>().toEqualTypeOf<'' | Base64url>();

expectTypeOf<
  v.InferOutput<typeof PEMSchema>
>().toEqualTypeOf<PEM>();
