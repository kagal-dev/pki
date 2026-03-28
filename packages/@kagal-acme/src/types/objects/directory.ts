// ACME directory (RFC 8555 §7.1.1)

/**
 * Directory metadata.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1}
 */
export interface DirectoryMeta {
  /** URL to terms of service. */
  termsOfService?: string
  /** CA information URL. */
  website?: string
  /** CAA hostnames. */
  caaIdentities?: string[]
  /** Whether EAB is required. */
  externalAccountRequired?: boolean
  /**
   * Profile name to description map
   * (draft-ietf-acme-profiles).
   *
   * @beta
   * @see {@link https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/}
   */
  profiles?: Record<string, string>
};

/**
 * ACME directory resource.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1}
 */
export interface Directory {
  /** Nonce endpoint URL. */
  newNonce: string
  /** Account creation URL. */
  newAccount: string
  /** Order creation URL. */
  newOrder: string
  /** Pre-authorisation URL (optional). */
  newAuthz?: string
  /** Revocation URL. */
  revokeCert: string
  /** Key rollover URL. */
  keyChange: string
  /**
   * ARI endpoint URL (RFC 9773 §3).
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-3}
   */
  renewalInfo?: string
  /** Server metadata. */
  meta?: DirectoryMeta
};
