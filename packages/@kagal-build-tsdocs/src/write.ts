// Document output and logging

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import type { DocumentsManifest } from './types';

/** Write per-export JSON files and a unified manifest. */
export function writeDocuments(
  outputDirectory: string,
  manifest: DocumentsManifest,
) {
  mkdirSync(outputDirectory, { recursive: true });

  // Per-export JSON files
  for (const [exportPath, entry] of
    Object.entries(manifest.exports)) {
    const filename = exportPath === '.' ?
      'index' :
      exportPath.replace('./', '');

    writeFileSync(
      path.resolve(outputDirectory, `${filename}.json`),
      JSON.stringify(entry.symbols, undefined, 2),
    );
  }

  // Unified manifest
  writeFileSync(
    path.resolve(outputDirectory, 'api.json'),
    JSON.stringify(manifest, undefined, 2),
  );
}

/** Log extraction summary. */
export function logDocuments(
  manifest: DocumentsManifest,
) {
  const exports = Object.keys(manifest.exports).length;
  const symbols = Object.values(manifest.exports)
    .reduce(
      (sum, entry) => sum + entry.symbolCount, 0,
    );

  console.log(
    `[docs] ${exports} exports, ${symbols} symbols`,
  );
}
