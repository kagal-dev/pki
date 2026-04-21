// @kagal/ca/signer types

/** Environment bindings for the Signer DO. */
export interface SignerEnv {
  /**
   * KEK bindings: `CA_KEK_v1`, `CA_KEK_v2`, etc.
   *
   * Each is a base64url-encoded AES-256 key.
   * The DO looks up the version matching the stored
   * `kek_version` and re-wraps if a newer version
   * is available.
   */
  [key: `CA_KEK_v${number}`]: string
}
