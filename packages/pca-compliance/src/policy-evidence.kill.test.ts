import { compilePolicy } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { frameworkReport } from './framework-report';

describe('soc2: policy evidence text', () => {
  const policy = compilePolicy({ permissions: { github: ['read'] } });
  const ev = (r: ReturnType<typeof frameworkReport>, id: string) => r.controls.find((c) => c.id === id)!.evidence;
  it('names the missing predicates for access and change control', () => {
    const r = frameworkReport('soc2', { policy: { ...policy, predicates: [] }, events: [] }, 0);
    expect(ev(r, 'cc6.1-access')).toBe('the supplied policy lists no predicates');
    expect(ev(r, 'cc8.1-change')).toBe('the supplied policy lists no predicates');
  });
  it('a policy whose predicates are not an array lists none', () => {
    const r = frameworkReport('soc2', { policy: { ...policy, predicates: undefined as never }, events: [] }, 0);
    expect(ev(r, 'cc6.1-access')).toBe('the supplied policy lists no predicates');
  });
});
