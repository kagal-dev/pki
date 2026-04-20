import { DurableObject } from 'cloudflare:workers';

import type { JWK, PEM } from '@kagal/acme/types';
import { decodeBase64url, jwkThumbprint } from '@kagal/acme/utils';
import { consola } from 'consola';

import type { SignerEnv } from './types';

/** ECDSA P-256 algorithm descriptor. */
const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;

/** ECDSA signing parameters. */
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

export class SignerDO extends DurableObject<SignerEnv> {
  private signingKey?: CryptoKey;

  private publicJWK?: JsonWebKey;
  private schemaReady = false;

  // public — key management

  /**
   * CA certificate chain for a specific key.
   *
   * @remarks
   * Phase 0a stub: always returns `undefined` until
   * the root-lifecycle work in chunk 0c populates
   * `chain_pem`.
   */
  async getChain(kid?: string): Promise<PEM | undefined> {
    consola.debug('getChain', { kid });
    return undefined;
  }

  /**
   * @deprecated Use {@link getPublicKeys} — returns
   * `[0]` of its result. Kept for the existing test
   * surface; will be removed once callers migrate.
   */
  async getPublicKey(): Promise<JsonWebKey> {
    await this.getSigningKey();
    return this.publicJWK!;
  }

  /**
   * All CA public keys, newest first.
   *
   * @remarks
   * Phase 0a: there is only ever one stored key, so
   * the result is `[publicJWK]` once bootstrapped or
   * `[]` before. Multi-version handling lands with
   * the rotation work.
   */
  async getPublicKeys(): Promise<JWK[]> {
    await this.getSigningKey();
    return [this.publicJWK as JWK];
  }

  /**
   * Sign data with a key picked by relative offset
   * from newest. `0` (default) is the latest, `-1`
   * the previous, and so on.
   *
   * @remarks
   * Positive offsets are **invalid** by definition —
   * no key is newer than the latest. This is a
   * permanent contract, not a Phase 0a limitation.
   *
   * Negative offsets reserve the historical-key
   * selection path. Phase 0a stores a single key
   * with no rotation history, so negatives throw a
   * "not yet" error today; they will become valid
   * once rotation lands.
   *
   * Return type is narrower than the {@link Signer}
   * contract by design (covariant) — pre-rotation,
   * the current-key path always succeeds.
   */
  async sign(
    data: BufferSource,
    offset?: number,
  ): Promise<ArrayBuffer> {
    if (offset !== undefined && offset > 0) {
      throw new Error(
        `invalid sign offset ${offset}: no key is newer than the latest`,
      );
    }
    if (offset !== undefined && offset < 0) {
      throw new Error(
        `sign offset ${offset} not yet supported (rotation pending)`,
      );
    }
    const key = await this.getSigningKey();
    return crypto.subtle.sign(ECDSA_SIGN, key, data);
  }

  // serial numbers

  /** Allocate and return the next certificate serial number. */
  async nextSerialNumber(): Promise<number> {
    this.initSchema();

    const rows = this.ctx.storage.sql.exec(
      'INSERT INTO serial_counter (id, last_serial) VALUES (1, 1)' +
      ' ON CONFLICT(id) DO UPDATE SET last_serial = last_serial + 1' +
      ' RETURNING last_serial',
    ).toArray();

    return rows[0].last_serial as number;
  }

  // ACME

  /**
   * Finalise an order: assign serial, sign with
   * CA key, return PEM certificate.
   */
  async finalizeOrder(
    csr: string,
    identifiers: import('@kagal/acme/types').Identifier[],
    profile?: string,
  ): Promise<string> {
    // TODO: assign serial, build TBS, sign with CA key
    consola.info('finalizeOrder', { csr, identifiers, profile });
    throw new Error('not implemented');
  }

  // internal — key lifecycle

  /**
   * Get the signing key, decrypting via KEK if not
   * already in memory. Generates a new key on first use.
   *
   * @param version - DAK version to load; latest if omitted.
   */
  private async getSigningKey(
    version?: number,
  ): Promise<CryptoKey> {
    if (this.signingKey) return this.signingKey;

    this.initSchema();

    // Try loading from SQLite
    const query = version === undefined ?
      'SELECT wrapped_key, wrap_iv, kek_version, public_jwk' +
      ' FROM signing_keys ORDER BY version DESC LIMIT 1' :
      'SELECT wrapped_key, wrap_iv, kek_version, public_jwk' +
      ' FROM signing_keys WHERE version = ?';

    const rows = version === undefined ?
      this.ctx.storage.sql.exec(query).toArray() :
      this.ctx.storage.sql.exec(query, version).toArray();

    if (rows.length > 0) {
      const row = rows[0];
      const kekVersion = row.kek_version as number;
      const kek = await this.importKEK(kekVersion);

      this.signingKey = await crypto.subtle.unwrapKey(
        'jwk',
        row.wrapped_key as ArrayBuffer,
        kek,
        { name: 'AES-GCM', iv: new Uint8Array(row.wrap_iv as ArrayBuffer) },
        ECDSA_P256,
        false,
        ['sign'],
      );

      this.publicJWK = JSON.parse(row.public_jwk as string);

      // TODO: re-wrap if kekVersion < current KEK version

      return this.signingKey;
    }

    // No stored key — generate a new one
    return this.newSigningKey();
  }

  /** Generate a new ECDSA P-256 key pair, wrap, and store. */
  private async newSigningKey(): Promise<CryptoKey> {
    const keyPair = await crypto.subtle.generateKey(
      ECDSA_P256, true, ['sign', 'verify'],
    );

    const publicJWK = await crypto.subtle.exportKey(
      'jwk', keyPair.publicKey,
    );

    // Wrap private key with current KEK
    const kekVersion = 1; // TODO: detect latest available
    const kek = await this.importKEK(kekVersion);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const wrappedKey = await crypto.subtle.wrapKey(
      'jwk', keyPair.privateKey, kek, { name: 'AES-GCM', iv },
    );

    // RFC 7638 thumbprint over required members only —
    // stable identifier across rotations, used as the
    // signed cert chain's lookup key in `chain_pem`.
    const kid = await jwkThumbprint(publicJWK as JWK);

    this.ctx.storage.sql.exec(
      'INSERT INTO signing_keys' +
      ' (wrapped_key, wrap_iv, kek_version, algorithm,' +
      '  public_jwk, kid)' +
      ' VALUES (?, ?, ?, ?, ?, ?)',
      wrappedKey,
      iv.buffer as ArrayBuffer,
      kekVersion,
      'ECDSA-P256',
      JSON.stringify(publicJWK),
      kid,
    );

    // Cache non-extractable copy for signing
    const privateJWK = await crypto.subtle.exportKey(
      'jwk', keyPair.privateKey,
    );
    this.signingKey = await crypto.subtle.importKey(
      'jwk', privateJWK, ECDSA_P256, false, ['sign'],
    );
    this.publicJWK = publicJWK;

    return this.signingKey;
  }

  /** Import a KEK version from env as an AES-GCM CryptoKey. */
  private importKEK(version: number): Promise<CryptoKey> {
    const b64 = this.env[`CA_KEK_v${version}`];
    if (!b64) {
      throw new Error(`CA_KEK_v${version} not found in env`);
    }

    return crypto.subtle.importKey(
      'raw',
      decodeBase64url(b64),
      'AES-GCM',
      false,
      ['wrapKey', 'unwrapKey'],
    );
  }

  /** Create the signing_keys table if it doesn't exist. */
  private initSchema(): void {
    if (this.schemaReady) return;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS signing_keys (
        version INTEGER PRIMARY KEY AUTOINCREMENT,
        wrapped_key BLOB NOT NULL,
        wrap_iv BLOB NOT NULL,
        kek_version INTEGER NOT NULL,
        algorithm TEXT NOT NULL,
        public_jwk TEXT NOT NULL,
        kid TEXT NOT NULL UNIQUE,
        chain_pem TEXT,
        created_at INTEGER NOT NULL DEFAULT (unixepoch())
      )
    `);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS serial_counter (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        last_serial INTEGER NOT NULL DEFAULT 0
      )
    `);
    this.schemaReady = true;
  }
}
