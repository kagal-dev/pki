import { newDocumentsHook } from '@kagal/build-tsdoc';
import { defineBuildConfig } from 'unbuild';

export default defineBuildConfig({
  declaration: true,
  sourcemap: true,

  hooks: {
    'build:done': newDocumentsHook(),
  },
});
