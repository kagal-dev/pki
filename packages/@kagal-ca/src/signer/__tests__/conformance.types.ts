// SignerDO ↔ Signer conformance — compile-time only.
// If SignerDO drifts from the Signer interface, tsc fails.

import { expectTypeOf } from 'vitest';

import type { Signer } from '../../server/types';
import type { SignerDO } from '../signer';

expectTypeOf<SignerDO>().toMatchTypeOf<Signer>();
