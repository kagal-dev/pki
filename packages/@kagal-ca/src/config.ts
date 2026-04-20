import { Directory } from '@kagal/acme/types';

export interface PathsConfig {
  base: string
  website?: string

  keyChange: string
  newAccount: string
  newAuthz?: string
  // RFC 8555 paths
  newNonce: string
  newOrder: string
  revokeCert: string
  termsOfService?: string

  revocationList: string
  // These paths are not defined in RFC 8555, but are commonly used by CAs.
  rootCert: string
  transparencyLog: string
}

export const DEFAULT_PATHS_CONFIG: PathsConfig = {
  base: 'https://kagal.example.com/ca/',

  newNonce: 'new-nonce',
  newAccount: 'new-account',
  newOrder: 'new-order',
  revokeCert: 'revoke-cert',
  keyChange: 'key-change',
  termsOfService: 'terms-of-service',

  // These paths are not defined in RFC 8555, but are commonly used by CAs.
  rootCert: 'root.crt',
  revocationList: 'crl',
  transparencyLog: 'ct',
};

const relativePathRE = /^(?!https?:\/\/|\/).+/;

function addPrefix(path: string, prefix: string): string {
  if (!relativePathRE.test(path)) {
    return path;
  }
  return prefix + path;
}

export function getDirectoryConfig(paths: PathsConfig): Directory {
  const { base, ...rest } = paths;

  const directory: Partial<Directory> = {};
  for (const [key, value] of Object.entries(rest)) {
    directory[key as keyof Directory] = addPrefix(value, base);
  }
  return directory as Directory;
}
