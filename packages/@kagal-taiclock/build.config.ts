import { newDocumentsHook } from '@kagal/build-tsdocs';
import { defineBuildConfig } from 'unbuild';

export default defineBuildConfig({
  entries: [
    { input: 'src/index', name: 'index' },
  ],
  declaration: true,
  sourcemap: true,

  hooks: {
    'build:done': newDocumentsHook(),
  },
});
