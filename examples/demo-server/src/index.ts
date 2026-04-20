import type { ServerConfig } from '@kagal/ca/server';
import type { SignerDO, SignerEnv } from '@kagal/ca/signer';
import { Server } from '@kagal/ca/server';
import { consola } from 'consola';
import { Hono } from 'hono';

interface Env extends SignerEnv {
  CA_REGISTRY: KVNamespace
  CA_SIGNER: DurableObjectNamespace<SignerDO>
}

const app = new Hono<{ Bindings: Env }>();

app.get('/', (c) => {
  return c.json({ name: 'kagal-demo-ca-server' });
});

app.get('/.well-known/acme', (c) => {
  return c.redirect('/acme/directory');
});

app.all('/acme/*', async (c) => {
  const signer = c.env.CA_SIGNER.get(c.env.CA_SIGNER.idFromName('ca'));

  const config: ServerConfig = {
    baseURL: 'http://localhost:8787/acme',
    signer,

    async resolveAccountKey(kid) {
      consola.info('resolveAccountKey', { kid });
      return undefined;
    },

    async resolveEABKey(keyID) {
      consola.info('resolveEABKey', { keyID });
      return undefined;
    },

    async checkPolicy(check) {
      consola.info('checkPolicy', { check });
      return undefined;
    },
  };

  return new Server(config).app.fetch(c.req.raw, c.env);
});

export default app;

// Re-exported so the `CA_SIGNER` Durable Object
// binding in wrangler.jsonc resolves to the class.
export { SignerDO } from '@kagal/ca/signer';
