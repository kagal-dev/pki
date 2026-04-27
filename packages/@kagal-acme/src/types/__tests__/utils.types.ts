// narrow type-narrowing helper assertions
//
// Compile-time only — these `expectTypeOf` calls
// produce no runtime output; the file is type-checked
// via tsconfig.tests.json but never executed by vitest
// (not a `*.test.ts` file). All imports are
// `import type`; every reference is in `typeof` /
// `ReturnType` / `Parameters` position.

import { expectTypeOf } from 'vitest';

import type { OrderStatus } from '../constants';
import type { narrow } from '../utils';

// narrow returns the union when membership holds, or
// `undefined`. If the return type ever drops the
// `undefined` branch (e.g. a refactor that throws on
// miss instead), this fires.
expectTypeOf<
  ReturnType<typeof narrow<OrderStatus>>
>().toEqualTypeOf<OrderStatus | undefined>();

// First parameter is a `ReadonlySet<T>`; second is
// plain `string` — the whole point is to narrow raw
// strings into a typed union. If `value` ever widens to
// `unknown`, the helper becomes a lie (it would claim
// any value is a member).
expectTypeOf<
  Parameters<typeof narrow<OrderStatus>>[0]
>().toEqualTypeOf<ReadonlySet<OrderStatus>>();
expectTypeOf<
  Parameters<typeof narrow<OrderStatus>>[1]
>().toEqualTypeOf<string>();
