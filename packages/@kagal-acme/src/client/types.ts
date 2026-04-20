// Client machine types (@kagal/acme/client)

import type { AcmeResponse } from '../server/types';
import type { JWK } from '../types/jws/jwk';
import type { FlattenedJWS } from
  '../types/jws/jws';
import type { Authorization } from
  '../types/objects/authorization';
import type { Challenge } from
  '../types/objects/challenge';
import type { Problem } from '../types/objects/problem';

/** Client lifecycle phase. */
export type ClientPhase =
  | 'authorizing' |
  'awaiting-challenge' |
  'awaiting-retry' |
  'done' |
  'failed' |
  'finalizing' |
  'idle' |
  'ordering' |
  'polling-cert' |
  'registering';

/** JSON-serialisable client state. */
export type ClientState = {
  [key: string]: unknown
  accountURL?: string
  certificate?: string
  error?: Problem
  nonce?: string
  phase: ClientPhase
};

/**
 * Client configuration and dependencies.
 *
 * Static configuration, HTTP transport, signing,
 * and challenge provisioning.
 */
export interface ClientConfig {
  /** Challenge preference selector. */
  challengePreference?: (
    authz: Authorization,
    available: Challenge[],
  ) => Challenge | undefined
  /** ACME directory URL. */
  directoryURL: string
  /** EAB credentials (if required). */
  eab?: { hmacKey: string; keyID: string }
  /**
   * Send a JWS-signed POST request.
   * The machine constructs the body.
   */
  post(
    url: string,
    body: FlattenedJWS,
  ): Promise<AcmeResponse>
  /** Account public key. */
  publicKey: JWK
  /** JWK thumbprint (RFC 7638). */
  thumbprint: string

  /** HEAD request for nonce retrieval. */
  head(
    url: string,
  ): Promise<{ headers: Record<string, string> }>

  /**
   * Sign the JWS signing input.
   *
   * Input is the ASCII string
   * `base64url(protected) + "." + base64url(payload)`.
   * Key material is external — the machine never
   * sees the private key.
   */
  sign(input: string): Promise<string>

  /** Provision a challenge response. */
  createChallenge(
    authz: Authorization,
    challenge: Challenge,
    keyAuthorization: string,
  ): Promise<void>

  /** Clean up after challenge completion. */
  removeChallenge(
    authz: Authorization,
    challenge: Challenge,
    keyAuthorization: string,
  ): Promise<void>
};

/** Resumable ACME client machine. */
export interface Client {
  /** Account URL (set after registration). */
  readonly accountURL: string | undefined
  /** Issued certificate PEM chain. */
  readonly certificate: string | undefined
  /** Error (set when phase is `'failed'`). */
  readonly error: Problem | undefined
  /** Current lifecycle phase. */
  readonly phase: ClientPhase
  /** Retry delay (set when `'awaiting-retry'`). */
  readonly retryAfterMS: number | undefined

  /** Whether renewal is due (ARI). */
  readonly needsRenewal: boolean
  /** Computed renewal time (unix ms, from ARI). */
  readonly suggestedRenewalAt: number | undefined

  /** Advance the flow. */
  resume(): Promise<void>
  /** Serialise to JSON-safe state. */
  serialize(): ClientState
};
