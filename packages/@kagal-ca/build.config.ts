import { newDocumentsHook } from '@kagal/build-tsdocs';
import { defineBuildConfig } from 'unbuild';

export default defineBuildConfig({
  entries: [
    'src/index',
    {
      input: 'src/signer/index',
      name: 'signer',
    },
  ],
  declaration: true,
  sourcemap: true,
  externals: [
    /^cloudflare:/,
  ],

  hooks: {
    'build:done': newDocumentsHook(),
  },
});
