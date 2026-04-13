# Changelog

All notable changes to `@kagal/ct` will be documented
in this file.

## [Unreleased]

### Added

- **types**: RFC 9162 Certificate Transparency types —
  SignedTreeHead, SignedCertificateTimestamp,
  SubmittedEntry, LogEntry, InclusionProof,
  ConsistencyProof — with `Base64` type alias
  (RFC 4648 §4)
- **schema**: Valibot validators for all types with
  `validate*()` convenience functions returning a
  discriminated `ValidationResult<T>`
- **schema**: `Base64Schema` for standard base64
  encoding validation, LogID decoded byte-count check
  (2–127 bytes per §4.4)
