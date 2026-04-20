// Server machine types (@kagal/acme/server)

import type { JWK } from '../types/jws/jwk';
import type { FlattenedJWS } from
  '../types/jws/jws';
import type { Identifier } from
  '../types/objects/identifier';
import type { Problem } from '../types/objects/problem';

/** Inbound ACME request event. */
export type ServerEvent = {
  /** Parsed flattened JWS body. */
  jws: FlattenedJWS
  /** Full request URL. */
  requestURL: string
};

/** ACME HTTP response constructed by the machine. */
export type AcmeResponse = {
  /** JSON response body. */
  body: unknown
  /** Response headers. */
  headers: Record<string, string>
  /** HTTP status code. */
  status: number
};

/** Result of processing one ACME request. */
export type ServerResult<S> = {
  /** HTTP response (absent for timer events). */
  response?: AcmeResponse
  /** Optional wake-up timer in milliseconds. */
  scheduleMS?: number
  /** New state — orchestrator persists this. */
  state: S
};

/**
 * Server machine function signature.
 *
 * Receives current state + inbound event + deps,
 * returns new state + response.
 */
export type ServerMachine<S> = (
  state: S,
  event: ServerEvent,
  deps: ServerConfig,
) => Promise<ServerResult<S>>;

/**
 * Policy check discriminated union.
 *
 * The machine provides context; the orchestrator
 * applies business rules.
 */
export type PolicyCheck =
  | {
    certURL: string
    reason?: number
    type: 'approve-revocation'
  } |
  {
    contacts?: string[]
    type: 'approve-account'
  } |
  {
    identifier: Identifier
    type: 'approve-authz'
  };

/**
 * Server-side dependencies.
 *
 * Only key material, signing, and policy — the
 * machine handles all ACME protocol logic internally.
 */
export interface ServerConfig {
  /**
   * Look up an account's public key by kid URL.
   * Returns `undefined` if not found.
   */
  resolveAccountKey(
    kid: string,
  ): Promise<JWK | undefined>

  /**
   * Look up an EAB HMAC key by key ID.
   * Returns `undefined` if not found or revoked.
   */
  resolveEABKey(
    keyID: string,
  ): Promise<string | undefined>

  /**
   * Produce a signed certificate from a verified CSR.
   *
   * The machine has already verified the CSR
   * (SANs + proof-of-possession). The implementation
   * may include additional steps (e.g. CT logging,
   * SCT embedding) before returning the final
   * PEM chain.
   */
  signCertificate(
    csr: string,
    identifiers: Identifier[],
    profile?: string,
  ): Promise<string>

  /**
   * Policy decision.
   *
   * Return `undefined` to approve, or a
   * {@link Problem} to reject with a specific
   * ACME error. Throw on infrastructure failures —
   * the machine catches and returns `serverInternal`.
   */
  checkPolicy(
    check: PolicyCheck,
  ): Promise<Problem | undefined>
};
