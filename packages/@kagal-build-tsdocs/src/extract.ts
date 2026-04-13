// Symbol extraction from TypeScript sources

import path from 'node:path';

import type { BuildContext } from 'unbuild';
import {
  buildDocumentation,
  type DocEntry,
} from 'tsdoc-markdown';

import type { DocumentsManifest } from './types';

function resolveExportPath(name: string | undefined) {
  return name === 'index' || !name ?
    '.' :
    `./${name}`;
}

function sanitiseFileNames(
  symbols: DocEntry[],
  rootDirectory: string,
) {
  for (const symbol of symbols) {
    if (symbol.fileName) {
      symbol.fileName = path.relative(
        rootDirectory, symbol.fileName,
      );
    }

    if (symbol.parameters) {
      sanitiseFileNames(
        symbol.parameters, rootDirectory,
      );
    }

    if (symbol.methods) {
      sanitiseFileNames(
        symbol.methods, rootDirectory,
      );
    }

    if (symbol.properties) {
      sanitiseFileNames(
        symbol.properties, rootDirectory,
      );
    }

    if (symbol.constructors) {
      for (const constructor of symbol.constructors) {
        if (constructor.parameters) {
          sanitiseFileNames(
            constructor.parameters, rootDirectory,
          );
        }
      }
    }
  }
}

function extractSymbols(
  inputFile: string,
  rootDirectory: string,
) {
  try {
    const symbols = buildDocumentation({
      inputFiles: [inputFile],
      options: { explore: true, types: true },
    });

    sanitiseFileNames(symbols, rootDirectory);
    return symbols;
  } catch (error) {
    const exportPath = resolveExportPath(
      path.basename(inputFile, '.ts'),
    );
    console.warn(
      `[docs] Failed for ${exportPath}:`, error,
    );
    return undefined;
  }
}

/** Extract documentation from all build entries. */
export function resolveDocuments(
  context: BuildContext,
): DocumentsManifest {
  const rootDirectory = context.options.rootDir;

  const manifest: DocumentsManifest = {
    name: context.options.name,
    version: context.pkg.version,
    generatedAt: new Date().toISOString(),
    exports: {},
  };

  for (const entry of context.options.entries) {
    const exportPath = resolveExportPath(entry.name);
    const symbols = extractSymbols(
      entry.input, rootDirectory,
    );

    if (symbols) {
      manifest.exports[exportPath] = {
        entryFile: path.relative(
          rootDirectory, entry.input,
        ),
        symbols,
        symbolCount: symbols.length,
      };
    }
  }

  return manifest;
}
