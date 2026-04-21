import type { SignerDO } from '../signer';
import type { SignerEnv } from '../types';

/** Test environment extending SignerEnv with DO binding. */
interface TestEnv extends SignerEnv {
  CA_SIGNER: DurableObjectNamespace<SignerDO>
}

declare global {
  namespace Cloudflare {
    // eslint-disable-next-line @typescript-eslint/no-empty-object-type
    interface Env extends TestEnv {}
  }
}
