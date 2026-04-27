// ACME encoding brand type assertions (RFC 7515 §2)
//
// Compile-time only — these `expectTypeOf` calls
// produce no runtime output; the file is type-checked
// via tsconfig.tests.json but never executed by vitest
// (not a `*.test.ts` file). All imports are
// `import type` — every referenced symbol is used in
// `typeof` / `ReturnType` / `Parameters` / `InferOutput`
// positions, so `/types/__tests__` keeps zero runtime
// edges into `/schema` and `/utils`.

import type * as v from 'valibot';
import { expectTypeOf } from 'vitest';

import type {
  asBase64url,
  asBase64urlAlphabet,
  asPEM,
  Base64url,
  Base64urlAlphabet,
  PEM,
} from '../encoding';

import type {
  Base64urlOrEmptySchema,
  Base64urlSchema,
  PEMSchema,
  validateBase64url,
  validateBase64urlOrEmpty,
  validatePEM,
  ValidationResult,
} from '../../schema';

import type {
  encodeBase64url,
  getRandom,
  jwkThumbprint,
} from '../../utils';

// -- brand asymmetry --

// A branded string is still a string: reads, concat,
// JSON.stringify, storage writes all work transparently.
expectTypeOf<Base64url>().toExtend<string>();
expectTypeOf<Base64urlAlphabet>().toExtend<string>();
expectTypeOf<PEM>().toExtend<string>();

// A plain string is NOT a branded value: writes require
// the brand, preventing silent mix-ups at call sites.
expectTypeOf<string>().not.toExtend<Base64url>();
expectTypeOf<string>().not.toExtend<Base64urlAlphabet>();
expectTypeOf<string>().not.toExtend<PEM>();

// -- brand disjointness --

// The three brands are pairwise disjoint. `Base64url`
// (byte-framed, decodable) and `Base64urlAlphabet`
// (alphabet-only, no decode framing) are intentionally
// non-interchangeable — a `Challenge.token` cannot be
// passed where a JWS signature is expected, and vice
// versa. PEM is text armour and disjoint from both.
expectTypeOf<Base64url>().not.toExtend<Base64urlAlphabet>();
expectTypeOf<Base64url>().not.toExtend<PEM>();
expectTypeOf<Base64urlAlphabet>().not.toExtend<Base64url>();
expectTypeOf<Base64urlAlphabet>().not.toExtend<PEM>();
expectTypeOf<PEM>().not.toExtend<Base64url>();
expectTypeOf<PEM>().not.toExtend<Base64urlAlphabet>();

// -- accessor signatures --

expectTypeOf<
  ReturnType<typeof asBase64url>
>().toEqualTypeOf<Base64url>();
expectTypeOf<
  ReturnType<typeof asBase64urlAlphabet>
>().toEqualTypeOf<Base64urlAlphabet>();
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
  Parameters<typeof asBase64urlAlphabet>[0]
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
