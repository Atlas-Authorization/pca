import { describe, expect, it } from 'vitest';
import { ActionKitError, parseParamShorthand } from '../src';

const thrown = (f: () => unknown): ActionKitError => {
  try {
    f();
  } catch (e) {
    return e as ActionKitError;
  }
  throw new Error('did not throw');
};

describe('param shorthand: no option is accepted by any bounded form', () => {
  it('an option named like an arbitrary phrase is refused by every form that takes no options', () => {
    for (const n of ['duration', 'text', 'string', 'message', 'int', 'count']) {
      const e = thrown(() => parseParamShorthand(`${n}(Stryker was here=1)`));
      expect(e).toBeInstanceOf(ActionKitError);
      expect([e.code, e.message]).toEqual(['bad_shorthand', `'${n}' has no option 'Stryker was here'`]);
    }
  });
});
