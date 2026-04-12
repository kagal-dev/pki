// ACME directory (RFC 8555 §7.1.1)

/**
 * Directory metadata.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1}
 */
export interface DirectoryMeta {
  /** CAA hostnames. */
  caaIdentities?: string[]
  /** Whether EAB is required. */
  externalAccountRequired?: boolean
  /** URL to terms of service. */
  termsOfService?: string
  /** CA information URL. */
  website?: string

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
  /** Key rollover URL. */
  keyChange: string
  /** Server metadata. */
  meta?: DirectoryMeta
  /** Account creation URL. */
  newAccount: string
  /** Pre-authorisation URL (optional). */
  newAuthz?: string
  /** Nonce endpoint URL. */
  newNonce: string
  /** Order creation URL. */
  newOrder: string
  /** Revocation URL. */
  revokeCert: string

  /**
   * ARI endpoint URL (RFC 9773 §3).
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-3}
   */
  renewalInfo?: string
};
