/** The source label recorded for each admitted document, including the fallbacks. */
import { describe, expect, it } from 'vitest';
import { createProvenanceRecorder } from '@atlasauth/pca';
import { withLangChainPcaFilter, withPcaFilter, type PolicyInput } from './index';

const policy: PolicyInput = [{ verb: 'can_view' }];
const ACL = { relation: 'can_view', object: 'document:a' };
const sources = (rec: ReturnType<typeof createProvenanceRecorder>) => rec.receipts().map((r) => `${r.origin}:${r.source}`);

describe('the recorded source of an admitted document', () => {
  it('a LangChain document with neither id nor source is recorded by its position', async () => {
    const rec = createProvenanceRecorder({ mediator: 'm', kid: 'k1' });
    const f = withLangChainPcaFilter({ invoke: () => [{ pageContent: 'c', metadata: { acl: ACL } }, { pageContent: 'c', metadata: { id: 'named', acl: ACL } }] as never }, 'user:alice', policy, { recorder: rec });
    await f.invoke('q');
    expect(sources(rec)).toEqual(['retrieval:doc#0', 'retrieval:named']);
  });
  it('an id reader that yields nothing, or throws, after the filter ran falls back to the position', async () => {
    const rec = createProvenanceRecorder({ mediator: 'm', kid: 'k1' });
    let armed = false;
    const opts = {
      // the recorder is read after the filter and before the sources are derived
      get recorder() {
        armed = true;
        return rec;
      },
      getId: (d: { id: string }): string => {
        if (!armed) return d.id;
        if (d.id === 'throws') throw new Error('unreadable');
        if (d.id === 'nothing') return undefined as unknown as string;
        return d.id;
      },
    };
    const docs = [
      { id: 'throws', acl: ACL },
      { id: 'nothing', acl: ACL },
      { id: 'ok', acl: ACL },
    ];
    const f = withPcaFilter({ retrieve: () => docs }, 'user:alice', policy, opts as never);
    expect((await f.retrieve('q')).length).toBe(3);
    expect(sources(rec)).toEqual(['retrieval:doc#0', 'retrieval:doc#1', 'retrieval:ok']);
  });
});
