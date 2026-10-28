import { runVectors } from '../src/runner.ts';
import { assert, each } from './harness.ts';

each('vectors replay through the reference subject with zero disagreements', [], (s) => {
  assert.deepEqual(runVectors(s), []);
});
