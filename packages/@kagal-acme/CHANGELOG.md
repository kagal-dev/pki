# Changelog

All notable changes to `@kagal/acme` will be documented
in this file.

## [Unreleased]

### Added

- **types**: `errorStatus` URN → HTTP-status table
  (`Readonly<Record<ErrorType, number>>`) following
  Boulder defaults, with RFC 9773 §7.4 locking
  `alreadyReplaced` to 409.
- **types**: `newProblem` and `newSubproblem` data
  factories returning plain objects for the
  `application/problem+json` wire form (RFC 7807,
  RFC 8555 §6.7.1). `status` is always emitted,
  derived from `errorStatus[urn]` unless overridden
  via `options.status`.

## [0.1.1] - 2026-05-07

### Added

- **utils**: New `/utils` sub-path with base64url codec
  (`encodeBase64url`, `decodeBase64url`,
  `decodeBase64urlOrEmpty`), `getRandom` for
  cryptographically random base64url tokens,
  `jwkThumbprint` (RFC 7638 SHA-256), `exportJWK`, and
  `parseJWK`.
- **types**: Branded primitives `Base64url`,
  `Base64urlAlphabet`, and `PEM` with unvalidated
  `asBase64url` / `asBase64urlAlphabet` / `asPEM`
  accessors at trust boundaries.
- **schema**: Brand-returning encoding validators
  (`validateBase64url`, `validateBase64urlOrEmpty`,
  `validatePEM`, `Base64urlSchema`,
  `Base64urlOrEmptySchema`, `PEMSchema`).
- **schema**: Tightened structural validation —
  `StrictIdentifierSchema` for client request payloads,
  URL validation across directory / order endpoints,
  RFC 3339 timestamp validation, picklist enforcement
  for status / type enums.

### Changed

- **deps**: `jose ^6.2.2 → ^6.2.3` (runtime dependency
  for /utils JWK support).
- **internal**: `/schema` and `/utils` now consume
  types via the `/types` barrel rather than reaching
  into specific files. The internal layout of `/types`
  is private implementation detail; no public API
  change.
- **package**: Removed redundant `main` / `module`
  fields (covered by the `exports` map).
- **types/schema**: `JWK.key_ops` and `JWK.x5c` typed
  as `string[]` (was `readonly string[]`); the
  matching `JWKSchema` members drop `v.readonly()`.
  RFC 7517 §4.3 does not mandate language-level
  immutability — this aligns with `jose.JWK` for
  direct interop in `/utils`.

### Removed

- **types**: `AuthorizationBase`, `ChallengeBase`, and
  `JWKBase` are no longer exported. They served only as
  in-file union components for the concrete sibling
  variants (`Authorization`, `HTTPChallenge` /
  `DNSChallenge` / `TLSALPNChallenge`, `ECJWK` /
  `OKPJWK` / `RSAJWK`); consumers always know which
  concrete shape they hold.

### Fixed

- **types/schema**: `Problem` no longer extends
  `Subproblem`, so the top-level `identifier` field
  no longer appears on the `Problem` type per RFC 8555
  §6.7.1 ("identifier MUST NOT be present at the top
  level"). Both shapes share a private `ProblemBase`
  carrying the RFC 7807 §3.1 fields. Conformance
  type-tests lock the divergence: `Subproblem` MUST
  have `identifier`, `Problem` MUST NOT.

## [0.1.0] - 2026-04-13

Initial release.

### Added

- **types**: Full RFC 8555 type definitions — Account,
  Authorization, Challenge, Directory, Identifier, Order,
  Problem — with const tuples, `ReadonlySet` constants,
  and `narrow()` type guard
- **types**: JWS/JWK types — `FlattenedJWS`,
  `JWSProtectedHeader`, `ACMEProtectedHeader`,
  `ACMERequestHeader`, and discriminated `JWK` union
  (EC, OKP, RSA)
- **types**: Request payload types — `NewAccount`,
  `NewOrder`, `NewAuthz`, `Finalize`, `RevokeCert`,
  `KeyChange`, `DeactivateAccount`,
  `DeactivateAuthorization`
- **types**: Extension types — ARI renewal info and
  `CertID` (RFC 9773), ACME Profiles
  (draft-ietf-acme-profiles), TLS-ALPN-01 (RFC 8737),
  IP identifiers (RFC 8738)
- **schema**: Valibot validators for all types and
  request payloads with `validate*()` convenience
  functions returning a discriminated
  `ValidationResult<T>`
- **schema**: `Base64urlSchema` and
  `StrictIdentifierSchema` for fine-grained input
  validation
