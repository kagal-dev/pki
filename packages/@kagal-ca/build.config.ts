import { newDocumentsHook } from '@kagal/build-tsdocs';
import { defineBuildConfig } from 'unbuild';

export default defineBuildConfig({
  declaration: true,
  sourcemap: true,

  hooks: {
    'build:done': newDocumentsHook(),
  },
});
