// newProblem / newSubproblem factory type assertions
// (RFC 7807, RFC 8555 §6.7 / §6.7.1)
//
// Compile-time only — these `expectTypeOf` calls
// produce no runtime output; the file is type-checked
// via tsconfig.tests.json but never executed by vitest
// (not a `*.test.ts` file). All imports are
// `import type`; every reference is in `typeof` /
// `ReturnType` / `Parameters` position.

import { expectTypeOf } from 'vitest';

import type { Identifier } from '../identifier';
import type {
  newProblem,
  NewProblemOptions,
  newSubproblem,
  Problem,
  Subproblem,
} from '../problem';

import type {
  errorStatus,
  ErrorType,
} from '../../constants';

// -- newProblem signature --

// If the return type ever widens (e.g. `Problem | undefined`
// from a defensive refactor), this fires.
expectTypeOf<
  ReturnType<typeof newProblem>
>().toEqualTypeOf<Problem>();

expectTypeOf<
  Parameters<typeof newProblem>[0]
>().toEqualTypeOf<ErrorType>();

expectTypeOf<
  Parameters<typeof newProblem>[1]
>().toEqualTypeOf<string | undefined>();

expectTypeOf<
  Parameters<typeof newProblem>[2]
>().toEqualTypeOf<NewProblemOptions | undefined>();

// -- newSubproblem signature --

expectTypeOf<
  ReturnType<typeof newSubproblem>
>().toEqualTypeOf<Subproblem>();

expectTypeOf<
  Parameters<typeof newSubproblem>[0]
>().toEqualTypeOf<ErrorType>();

expectTypeOf<
  Parameters<typeof newSubproblem>[1]
>().toEqualTypeOf<Identifier | undefined>();

expectTypeOf<
  Parameters<typeof newSubproblem>[2]
>().toEqualTypeOf<string | undefined>();

// -- errorStatus shape --

// errorStatus[type] returns `number` for any ErrorType.
// If the table ever widens (e.g. typed
// `Partial<Record<ErrorType, number>>`), the indexed
// access would become `number | undefined` and this
// fires.
expectTypeOf<
  (typeof errorStatus)[ErrorType]
>().toEqualTypeOf<number>();
