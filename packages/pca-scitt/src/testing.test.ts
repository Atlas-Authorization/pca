import { expect, it } from 'vitest';
import * as main from './index';
import * as testing from './testing';

it('the in-memory reference log and store are only on /testing, never on the main entry', () => {
  expect(Object.keys(testing).sort()).toEqual(['MemoryScittLogStore', 'TransparencyService', 'registerStatement']);
  for (const n of ['TransparencyService', 'registerStatement', 'MemoryScittLogStore']) expect(Object.keys(main)).not.toContain(n);
});
