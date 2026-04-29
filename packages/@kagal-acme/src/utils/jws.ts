// ACME JWS parse + verify (RFC 7515, RFC 8555 §6)

import { flattenedVerify } from 'jose';

import type { JWK } from '../types/jws/jwk';
import type {
  ACMERequestHeader,
  FlattenedJWS,
} from '../types/jws/jws';
import { ProblemError } from '../error/problem';
import {
  validateACMERequestHeader,
  validateACMESignAlgorithm,
  validateFlattenedJWS,
} from '../schema';
import { acmeSignAlgorithms } from '../types/jws/alg';

import { decodeBase64url } from './encoding';

const textDecoder = new TextDecoder();

/**
 * Resolve the {@link JWK} that verifies an ACME request
 * JWS.
 *
 * @remarks
 * Called after the protected header has been structurally
 * validated (jwk XOR kid, nonce + url present, `alg` is an
 * ACME-approved asymmetric algorithm) and the `url` header
 * matches `expectedURL`, but before any signature check.
 * The request is not yet authenticated, so resolvers must
 * only **read** state — nonce consumption and any other
 * writes belong after {@link parseJWS} returns
 * successfully.
 *
 * - `header.jwk` present — newAccount / revokeCert-by-
 *   cert-key; callers return `header.jwk`, optionally
 *   after policy checks such as key-strength or
 *   blocklist lookups.
 * - `header.kid` present — all other requests; callers
 *   look up the account record by URL and return its
 *   public key.
 *
 * Throwing from the resolver aborts {@link parseJWS}
 * before jose ever sees the JWS — useful for surfacing
 * "unknown account" or "deactivated account" as distinct
 * errors from signature failures.
 */
export type ResolveKey = (
  header: ACMERequestHeader,
) => Promise<JWK>;

/**
 * Result of {@link parseJWS} — the verified protected
 * header, the decoded payload, and the validated JWS.
 *
 * @remarks
 * `payload` is `undefined` for POST-as-GET requests
 * (RFC 8555 §6.3), otherwise it is the JSON-parsed
 * payload. Callers narrow `payload` against the schema
 * for the specific ACME endpoint.
 */
export type ParsedJWS = {
  /** Validated flattened JWS (for audit / replay storage). */
  jws: FlattenedJWS
  /** Decoded payload (JSON) or `undefined` for POST-as-GET. */
  payload: unknown
  /** Verified protected header (jwk XOR kid). */
  protectedHeader: ACMERequestHeader
};

/**
 * Decode, validate, and cryptographically verify an ACME
 * request JWS (RFC 8555 §6).
 *
 * @param body - structured input as received from the
 *   request body (typically the result of
 *   `await request.json()`). A raw string must be
 *   JSON-parsed by the caller first.
 * @param expectedURL - absolute request URL the server is
 *   handling; compared against the JWS `url` header per
 *   RFC 8555 §6.4. Exact string match — normalisation
 *   (trailing slash, case, default ports) is the caller's
 *   responsibility. `expectedURL` itself is not
 *   validated; pass the exact URL the JWS must have been
 *   signed for.
 * @param resolveKey - callback returning the {@link JWK}
 *   to verify the signature with; see
 *   {@link ResolveKey}.
 *
 * @returns a {@link ParsedJWS} with the verified header,
 *   decoded payload, and validated JWS.
 *
 * @throws {@link ProblemError} carrying the RFC 7807
 *   document the ACME server should return on the wire.
 *   URN map per RFC 8555 §6.7:
 *
 *   - structural failure (outer JWS shape, header
 *     non-JSON, header schema, URL mismatch, payload
 *     non-JSON) → `malformed`
 *   - unsupported `alg` → `badSignatureAlgorithm`
 *   - signature verification failure → `unauthorized`
 *
 *   Errors thrown by `resolveKey` pass through unchanged
 *   — the caller decides their URN (e.g.
 *   `accountDoesNotExist`, `unauthorized`).
 *
 * @remarks
 * Stateless concerns only. `kid` → account resolution is
 * the caller's job, injected via {@link ResolveKey}.
 * Nonce consumption (replay defence, RFC 8555 §6.5) must
 * happen after a successful return — not from inside the
 * resolver, which sees an as-yet-unverified header. A
 * structurally missing or empty `nonce` surfaces here as
 * `malformed` (the field is absent or wrong-shape on the
 * wire); `badNonce` semantics — replay, expired, never
 * issued — belong to the caller's nonce store after this
 * function returns.
 *
 * Validation order: outer-JWS schema → header decode →
 * `alg` pre-check (so an unsupported algorithm surfaces
 * as `badSignatureAlgorithm` instead of being folded
 * into the catch-all `malformed`) → header schema →
 * URL match → `resolveKey` → signature verify → payload
 * decode. A malformed or `alg`-disallowed header rejects
 * before any resolver I/O — resolvers may safely assume
 * the header passed `ACMERequestHeaderSchema`. The
 * verify call additionally pins jose to
 * {@link acmeSignAlgorithms} as defence in depth — an
 * outer-JWS `HS*` is already rejected by the schema,
 * but the pin keeps the guarantee at the crypto
 * boundary too.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2}
 */
export async function parseJWS(
  body: unknown,
  expectedURL: string,
  resolveKey: ResolveKey,
): Promise<ParsedJWS> {
  const jwsResult = validateFlattenedJWS(body);
  if (!jwsResult.success) {
    throw ProblemError.malformed('invalid Flattened JWS', {
      cause: jwsResult.issues,
    });
  }
  const jws = jwsResult.data;

  const headerBytes = decodeBase64url(jws.protected);
  const headerJSON = textDecoder.decode(headerBytes);
  let headerRaw: unknown;
  try {
    headerRaw = JSON.parse(headerJSON);
  } catch (error) {
    throw ProblemError.malformed(
      'JWS protected header is not valid JSON',
      { cause: error },
    );
  }

  if (
    typeof headerRaw === 'object' &&
    headerRaw !== null &&
    'alg' in headerRaw
  ) {
    const algResult = validateACMESignAlgorithm(headerRaw.alg);
    if (!algResult.success) {
      throw ProblemError.of(
        'urn:ietf:params:acme:error:badSignatureAlgorithm',
        `unsupported JWS signature algorithm: ${
          String(headerRaw.alg)
        }`,
        { cause: algResult.issues },
      );
    }
  }

  const headerResult = validateACMERequestHeader(headerRaw);
  if (!headerResult.success) {
    throw ProblemError.malformed(
      'invalid ACME protected header',
      { cause: headerResult.issues },
    );
  }
  const protectedHeader = headerResult.data;

  if (protectedHeader.url !== expectedURL) {
    throw ProblemError.malformed(
      'JWS url does not match request URL',
      {
        cause: {
          expected: expectedURL,
          received: protectedHeader.url,
        },
      },
    );
  }

  const jwk = await resolveKey(protectedHeader);

  try {
    await flattenedVerify(jws, jwk, {
      algorithms: [...acmeSignAlgorithms],
    });
  } catch (error) {
    throw ProblemError.unauthorized(
      'JWS signature verification failed',
      { cause: error },
    );
  }

  const payloadText = jws.payload === '' ?
    '' :
    textDecoder.decode(decodeBase64url(jws.payload));
  let payload: unknown;
  if (payloadText !== '') {
    try {
      payload = JSON.parse(payloadText);
    } catch (error) {
      throw ProblemError.malformed(
        'JWS payload is not valid JSON',
        { cause: error },
      );
    }
  }

  return { jws, payload, protectedHeader };
}
