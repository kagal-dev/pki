# Changelog

All notable changes to `@kagal/acme` will be documented
in this file.

## [Unreleased]

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
