# Changelog

All notable changes to `@kagal/acme` will be documented
in this file.

## [Unreleased]

### Added

- **error**: New `/error` sub-path with `ProblemError`
  and `SubproblemError` Error subclasses wrapping the
  Problem document factories from `/types`. Both layers
  produce the same RFC 7807 wire document — wrappers
  delegate to the factories — so callers mix
  return-a-Problem and throw-a-Problem patterns per
  call-site contract. Static helpers: `.of`,
  `.malformed`, `.unauthorized`, `.serverInternal`,
  `.compound` on `ProblemError`; `.of`,
  `.rejectedIdentifier`, `.caa` on `SubproblemError`,
  with HTTP status derived from `errorStatus[urn]`
  unless overridden via `options.status`.
  `ProblemError.compound` accepts mixed `Subproblem`
  documents and `SubproblemError` instances, unwrapping
  the latter and deep-copying the array so post-throw
  mutation cannot leak into the wire form.
- **schema**: `ACMESignAlgorithmSchema` (picklist over
  `acmeSignAlgorithms`) and the matching
  `validateACMESignAlgorithm` validator. Lets callers
  validate `alg` independently of the full header
  schema so an unsupported algorithm surfaces as
  `badSignatureAlgorithm` (RFC 8555 §6.7) rather than
  the catch-all `malformed`. The two ACME header bases
  now compose the named schema internally; behaviour
  unchanged.
- **schema**: CSR schemas — `CSRSchema`,
  `DistinguishedNameSchema`, `KeyUsageSchema`,
  `BasicConstraintsSchema`,
  `AuthorityInfoAccessSchema`, `ExtensionSchema`, plus
  matching `validateXxx` wrappers. Conform to the
  hand-written types via bidirectional `expectTypeOf`
  checks.
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
- **types**: `CSR` (decoded PKCS#10 + RFC 5280 TBS
  slots the orchestrator amends before the signer
  assembles the certificate), `DistinguishedName`
  (`Array<Record<string, string[]>>`, structurally
  compatible with `@peculiar/x509`'s `JsonName`),
  `KeyUsage`, `ExtendedKeyUsage`, `BasicConstraints`,
  `AuthorityInfoAccess`, `Extension`.
- **utils**: `parseJWS` — canonical decode +
  structural-validate + crypto-verify entry point for
  ACME outer-JWS requests (RFC 7515 §7.2.2 + RFC 8555
  §6). Three positional arguments (raw body, expected
  URL, `ResolveKey` callback). Returns a `ParsedJWS`
  with the verified protected header, decoded payload
  (or `undefined` for POST-as-GET per §6.3), and the
  validated JWS for audit / replay storage. Failures
  throw `ProblemError` with the §6.7 URN already
  resolved (`malformed`, `badSignatureAlgorithm`,
  `unauthorized`); errors thrown by the resolver pass
  through unchanged so callers keep control of their
  own URNs.
- **utils**: `parseCSR(pem)` decodes a PKCS#10 CSR
  (RFC 2986, RFC 8555 §7.4), verifies the
  proof-of-possession self-signature, and returns a
  fail-closed `CSR` tree. Throws `ProblemError` with
  the §6.7 URN already mapped: `malformed` (PEM
  armour broken, wrong label, undecodable DER),
  `badCSR` (PoP verification failure), `badPublicKey`
  (subject public key cannot be exported as a JWK),
  or a `compound` Problem aggregating one
  `unsupportedIdentifier` Subproblem per non-`dns`
  / non-`ip` SAN entry. Companion `decodePEM` (single-
  block RFC 7468 decoder, rejects multi-block input
  and label mismatches), `encodePEM` (branded PEM
  encoder), and extension extractors
  (`findExtension`, `findExtensionByType`,
  `findSANExtension`, `extractSANIdentifiers`,
  `extractBasicConstraints`, `extractKeyUsage`,
  `extractExtendedKeyUsage`,
  `extractCertificatePolicies`,
  `extractAuthorityInfoAccess`,
  `extractCRLDistributionPoints`,
  `extractRemainingExtensions`) exposed for reuse in
  the future `@kagal/ca` cert-parsing path.
  `extractSANIdentifiers` preserves SAN multiplicity
  exactly as it appears in the CSR — deduplication,
  IPv6 canonicalisation, and DNS case folding are
  consumer concerns.

### Changed

- **deps**: `@peculiar/x509` ^2.0.0 and
  `reflect-metadata` ^0.2.2 added as runtime
  dependencies for CSR / PEM / x509 reflection.

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
