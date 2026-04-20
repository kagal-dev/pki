import type { SignerDO } from '../../signer/signer';
import type { SignerEnv } from '../../signer/types';
import type { CAEnv } from '../../types';

/** Test environment extending CAEnv with DO bindings. */
interface TestEnv extends CAEnv, SignerEnv {
  CA_SIGNER: DurableObjectNamespace<SignerDO>
}

declare global {
  namespace Cloudflare {
    // eslint-disable-next-line @typescript-eslint/no-empty-object-type
    interface Env extends TestEnv {}
  }
}
