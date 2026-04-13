import { defineBuildConfig } from 'unbuild';

export default defineBuildConfig({
  entries: [
    { input: 'src/index', name: 'index' },
    { input: 'src/types/index', name: 'types' },
    { input: 'src/schema/index', name: 'schema' },
  ],
  declaration: true,
  sourcemap: true,
});
