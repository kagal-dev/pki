// @kagal/ca Server — challenge-less EAB ACME CA
// with CRL + CT for Cloudflare Workers

import type { Directory } from '@kagal/acme/types';
import { Hono } from 'hono';

import type { ServerConfig } from './types';

/**
 * Challenge-less EAB ACME CA with CRL and CT,
 * built on Hono for Cloudflare Workers.
 * Driven by dependency injection.
 */
export class Server {
  readonly app: Hono;

  private readonly config: ServerConfig;

  constructor(config: ServerConfig) {
    this.config = config;
    this.app = new Hono();

    this.setupRoutes();
  }

  private setupRoutes(): void {
    this.app.get('/directory', (c) => {
      return c.json(this.getDirectory());
    });

    // HEAD is handled automatically by Hono from GET
    this.app.get('/new-nonce', (c) => {
      c.header('Replay-Nonce', this.newNonce());
      c.header(
        'Cache-Control',
        'no-store, no-cache, must-revalidate',
      );
      // eslint-disable-next-line unicorn/no-null
      return c.body(null, 204);
    });
  }

  /** Build the ACME directory object. */
  private getDirectory(): Directory {
    const { baseURL, meta } = this.config;

    return {
      newNonce: `${baseURL}/new-nonce`,
      newAccount: `${baseURL}/new-account`,
      newOrder: `${baseURL}/new-order`,
      revokeCert: `${baseURL}/revoke-cert`,
      keyChange: `${baseURL}/key-change`,
      meta,
    };
  }

  /** Generate a replay nonce. */
  private newNonce(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return btoa(String.fromCodePoint(...bytes))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replace(/=+$/, '');
  }
}
