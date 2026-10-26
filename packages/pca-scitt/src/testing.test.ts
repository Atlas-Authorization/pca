import { expect, it } from 'vitest';
import * as main from './index';
import * as testing from './testing';

it('/testing re-exports exactly the reference log and registerStatement from the main entry', () => {
  expect(Object.keys(testing).sort()).toEqual(['TransparencyService', 'registerStatement']);
  expect(testing.TransparencyService).toBe(main.TransparencyService);
  expect(testing.registerStatement).toBe(main.registerStatement);
});
