// @kagal/ca/server types

import type {
  Directory,
  Identifier,
  JWK,
  PEM,
} from '@kagal/acme/types';

import type {
  ServerConfig as AcmeServerConfig,
} from '@kagal/acme/server';

/**
 * Pluggable signing authority interface.
 *
 * Defines the operations the CA server needs from its
 * signing backend. {@link SignerDO} is the reference
 * implementation; consumers can provide alternatives
 * (KMS, HSM, etc.).
 *
 * @remarks
 * **Three names, one key:** versions, offsets, and kids
 * all point at a signing key.
 *
 * - `version: number` — SQL primary key, autoincrement,
 *   `≥ 1`; **highest is latest**. Signer-internal; never
 *   crosses the DO boundary for anything a relying party
 *   sees.
 * - `offset: number` — API parameter on {@link sign};
 *   `≤ 0`; **`0` is latest**, `-1` the one before.
 *   Non-positive by convention so it can never be
 *   mistaken for a version.
 * - `kid: string` — RFC 7638 thumbprint; the stable
 *   external identifier used in URLs, JWS `kid` headers,
 *   and JWK Set entries.
 *
 * **Error contract:** Accessors return `undefined` on
 * domain failures (unknown kid, out-of-range offset,
 * pre-bootstrap reads). {@link getPublicKeys} returns
 * `[]` pre-bootstrap, never throws for "no keys yet".
 * Mutations ({@link finalizeOrder}) throw on validation
 * failure. Infrastructure failures (storage down, KEK
 * unavailable, WebCrypto rejection) always throw
 * regardless of method kind.
 */
export interface Signer {
  /**
   * Finalise an ACME order: verify CSR, render the
   * profile template, build the TBS, sign with the
   * current CA key, return the certificate. Serial
   * allocation is internal.
   *
   * @remarks
   * Phase 1 extends this to append to CT and securelog
   * before the final signature.
   */
  finalizeOrder(
    csr: PEM,
    identifiers: Identifier[],
    profile?: string,
  ): Promise<PEM>

  /**
   * CA certificate chain (root last) for a specific
   * key. Without `kid`, returns the chain for the
   * current key; with `kid`, the chain rooted in that
   * key version. Returns `undefined` when the kid is
   * unknown or no chain has been installed yet.
   */
  getChain(kid?: string): Promise<PEM | undefined>

  /**
   * @deprecated Use {@link getPublicKeys} — returns
   * `[0]` of the new method's result. Will be removed
   * once tests and callers migrate.
   */
  getPublicKey(): Promise<JsonWebKey>

  /**
   * All CA public keys, newest first. `[0]` is the
   * current signing key; retired keys remain so
   * relying parties can verify historical signatures.
   * Each JWK carries its `kid` (RFC 7638 thumbprint),
   * `use: 'sig'`, and `alg`.
   *
   * @remarks
   * Returns `[]` pre-bootstrap. The consumer worker
   * wraps the result in `{ keys: [...] }` to serve
   * `/.well-known/jwks.json` (RFC 7517 §5).
   */
  getPublicKeys(): Promise<JWK[]>

  /**
   * @deprecated Will be demoted to private on
   * {@link SignerDO} once internal call sites migrate;
   * not part of the long-term {@link Signer} contract.
   */
  nextSerialNumber(): Promise<number>

  /**
   * Sign data with a key picked by relative offset
   * from newest: `0` (default) is the latest, `-1` is
   * the previous, and so on. The parameter is always
   * `≤ 0` — positive values are reserved for absolute
   * versions (which are SignerDO-internal and not
   * exposed on this interface). Returns `undefined`
   * when the offset points past the oldest stored
   * key, or when no keys exist yet.
   */
  sign(
    data: BufferSource,
    offset?: number,
  ): Promise<ArrayBuffer | undefined>
}

/**
 * CA server configuration and dependencies.
 *
 * @remarks
 * Extends `@kagal/acme/server`'s `ServerConfig` minus
 * `signCertificate`, and adds a pluggable {@link Signer}.
 * The CA bridges `signCertificate` →
 * `signer.finalizeOrder` internally at the acme-machine
 * call site, so the acme server machine sees the
 * standard callback and consumers inject a `Signer`
 * impl instead of an ACME-level signing callback.
 *
 * `baseURL` and `meta?` are CA-specific additions used
 * to construct the ACME directory document; they are
 * not part of the acme `ServerConfig`.
 */
export interface ServerConfig
  extends Omit<AcmeServerConfig, 'signCertificate'> {
  /** Base URL for constructing ACME resource URLs. */
  baseURL: string

  /** ACME directory metadata. */
  meta?: Directory['meta']

  /**
   * Pluggable signing backend. Replaces the acme-level
   * `signCertificate` callback — the CA derives
   * `signCertificate` from `signer.finalizeOrder`.
   */
  signer: Signer
}
