/** ACME error type URNs. */
export const errorTypes = [
  // RFC 8555 §6.7
  'urn:ietf:params:acme:error:accountDoesNotExist',
  'urn:ietf:params:acme:error:alreadyRevoked',
  'urn:ietf:params:acme:error:badCSR',
  'urn:ietf:params:acme:error:badNonce',
  'urn:ietf:params:acme:error:badPublicKey',
  'urn:ietf:params:acme:error:badRevocationReason',
  'urn:ietf:params:acme:error:badSignatureAlgorithm',
  'urn:ietf:params:acme:error:caa',
  'urn:ietf:params:acme:error:compound',
  'urn:ietf:params:acme:error:connection',
  'urn:ietf:params:acme:error:dns',
  'urn:ietf:params:acme:error:externalAccountRequired',
  'urn:ietf:params:acme:error:incorrectResponse',
  'urn:ietf:params:acme:error:invalidContact',
  'urn:ietf:params:acme:error:malformed',
  'urn:ietf:params:acme:error:orderNotReady',
  'urn:ietf:params:acme:error:rateLimited',
  'urn:ietf:params:acme:error:rejectedIdentifier',
  'urn:ietf:params:acme:error:serverInternal',
  'urn:ietf:params:acme:error:tls',
  'urn:ietf:params:acme:error:unauthorized',
  'urn:ietf:params:acme:error:unsupportedContact',
  'urn:ietf:params:acme:error:unsupportedIdentifier',
  'urn:ietf:params:acme:error:userActionRequired',
  // RFC 9773 §7.4
  'urn:ietf:params:acme:error:alreadyReplaced',
  // draft-ietf-acme-profiles §6
  'urn:ietf:params:acme:error:invalidProfile',
] as const;

/**
 * ACME error type union.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-7.4}
 * @see {@link https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/}
 */
export type ErrorType = (typeof errorTypes)[number];

/** Runtime set of valid ACME error types. */
export const ErrorTypes: ReadonlySet<ErrorType> = new Set(errorTypes);

// cspell:words probs
/**
 * Default HTTP status code per ACME error type.
 *
 * @remarks
 * RFC 8555 §6.7 does not specify HTTP statuses for the
 * error URNs. Values here follow Let's Encrypt's
 * Boulder reference implementation
 * ({@link https://github.com/letsencrypt/boulder/blob/main/probs/probs.go | probs/probs.go}).
 *
 * Exceptions:
 * - `alreadyReplaced` is fixed at 409 by RFC 9773 §7.4
 *   (`MUST return an HTTP 409 (Conflict)`).
 * - `compound`, `externalAccountRequired`,
 *   `incorrectResponse`, and `userActionRequired` are
 *   not emitted by Boulder; the values here are
 *   defensible defaults.
 *
 * Boulder also re-uses `malformed` with non-default
 * statuses (404, 405) for occurrence-specific cases.
 * Callers needing the same pattern should pass
 * `options.status` to {@link newProblem}.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-7.4}
 */
export const errorStatus: Readonly<Record<ErrorType, number>> = {
  // 400 Bad Request
  'urn:ietf:params:acme:error:accountDoesNotExist': 400,
  'urn:ietf:params:acme:error:alreadyRevoked': 400,
  'urn:ietf:params:acme:error:badCSR': 400,
  'urn:ietf:params:acme:error:badNonce': 400,
  'urn:ietf:params:acme:error:badPublicKey': 400,
  'urn:ietf:params:acme:error:badRevocationReason': 400,
  'urn:ietf:params:acme:error:badSignatureAlgorithm': 400,
  'urn:ietf:params:acme:error:compound': 400,
  'urn:ietf:params:acme:error:connection': 400,
  'urn:ietf:params:acme:error:dns': 400,
  'urn:ietf:params:acme:error:incorrectResponse': 400,
  'urn:ietf:params:acme:error:invalidContact': 400,
  'urn:ietf:params:acme:error:invalidProfile': 400,
  'urn:ietf:params:acme:error:malformed': 400,
  'urn:ietf:params:acme:error:rejectedIdentifier': 400,
  'urn:ietf:params:acme:error:tls': 400,
  'urn:ietf:params:acme:error:unsupportedContact': 400,
  'urn:ietf:params:acme:error:unsupportedIdentifier': 400,
  // 401 Unauthorized
  'urn:ietf:params:acme:error:externalAccountRequired': 401,
  // 403 Forbidden
  'urn:ietf:params:acme:error:caa': 403,
  'urn:ietf:params:acme:error:orderNotReady': 403,
  'urn:ietf:params:acme:error:unauthorized': 403,
  'urn:ietf:params:acme:error:userActionRequired': 403,
  // 409 Conflict
  'urn:ietf:params:acme:error:alreadyReplaced': 409,
  // 429 Too Many Requests
  'urn:ietf:params:acme:error:rateLimited': 429,
  // 500 Internal Server Error
  'urn:ietf:params:acme:error:serverInternal': 500,
};
