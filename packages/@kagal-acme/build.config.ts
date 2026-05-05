import { newDocumentsHook } from '@kagal/build-tsdoc';
import { defineBuildConfig } from 'unbuild';

export default defineBuildConfig({
  entries: [
    { input: 'src/index', name: 'index' },
    { input: 'src/types/index', name: 'types' },
    { input: 'src/schema/index', name: 'schema' },
    { input: 'src/utils/index', name: 'utils' },
    { input: 'src/client/index', name: 'client' },
    { input: 'src/server/index', name: 'server' },
  ],
  declaration: true,
  sourcemap: true,

  hooks: {
    'build:done': newDocumentsHook(),
  },
});
