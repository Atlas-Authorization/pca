import { expect, it } from 'vitest';
import { run } from './test-support/flow-nl-review';

it('generate-then-review: a model draft needs a pinned reviewer signature before an agent exists', async () => {
  const r = await run();
  expect(r.refusedWithoutApproval).toContain('reviewer_not_pinned');
  expect(r.verbs).toEqual(['stripe.refund']);
});
