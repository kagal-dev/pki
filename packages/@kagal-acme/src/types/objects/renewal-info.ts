// ARI extension types (RFC 9773)

/**
 * ARI certificate identifier —
 * `base64url(AKI) + "." + base64url(Serial)`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-4.1}
 */
export type CertID = string;

/**
 * Renewal information (RFC 9773 §4).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-4}
 */
export interface RenewalInfo {
  /** Suggested renewal window. */
  suggestedWindow: {
    /** RFC 3339 end timestamp. */
    end: string
    /** RFC 3339 start timestamp. */
    start: string
  }

  /** URL explaining the renewal suggestion. */
  explanationURL?: string
};
