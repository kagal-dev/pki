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
