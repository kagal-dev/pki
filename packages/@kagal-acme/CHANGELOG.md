# Changelog

All notable changes to `@kagal/acme` will be documented
in this file.

## [Unreleased]

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
- **package**: Removed redundant `main` / `module`
  fields (covered by the `exports` map).

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
