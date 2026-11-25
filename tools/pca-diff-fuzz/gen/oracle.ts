// TS reference oracle (wire format v2): runs the SAME corpus.jsonl through @atlasauth/pca (source, via tsx).
//   tsx gen/oracle.ts <corpus.jsonl> <oracle.jsonl>
//
// verify case: {raw = PCActn JSON TEXT, grant = grant JSON text, now, aud}. The PCActn goes through the strict JSON profile
// (decodePCActn); a parse failure is a `wire` failure. Verdict shape matches conformance/README.md: a wire failure is terminal
// ({wire:false} only); otherwise all eight checks in normative order.
// canon case: strict parse + strict canonical form + hash of ANY JSON text (parse/profile failure => error).
import { readFileSync, writeFileSync } from 'node:fs';
import * as pca from '../../../packages/pca/src/index';
import { safeParse } from './safejson';

const [inp, outp] = process.argv.slice(2);
const lines = readFileSync(inp!, 'utf8').split('\n').filter(Boolean);
const out: string[] = [];
const CK = [['version', 'version'], ['audience', 'audience'], ['validity', 'validity'], ['chain', 'cap_chain'], ['grant_ref_bound', 'grant_ref_bound'], ['plan_inclusion', 'plan_inclusion'], ['leaf_signature', 'leaf_signature'], ['counter_format', 'counter_format']] as const;
async function main() {
  for (const line of lines) {
    const c = JSON.parse(line);
    const r: Record<string, unknown> = { id: c.id };
    try {
      if (c.kind === 'verify') {
        let p: pca.PCActn | undefined;
        try { p = pca.decodePCActn(c.raw); } catch { /* wire failure */ }
        if (p === undefined) { r.allow = false; r.checks = { wire: false }; r.reason = 'wire: parse'; out.push(JSON.stringify(r)); continue; }
        const grant = safeParse(c.grant) as pca.Capability;
        const g = await pca.verifyPCActnCore(p, { grant, nowEpoch: c.now, audience: c.aud });
        r.allow = g.allow;
        r.checks = g.checks.wire === 'fail' ? { wire: false } : Object.fromEntries([['wire', true], ...CK.map(([k, t]) => [k, g.checks[t] === 'pass'])]);
        r.reason = g.reason ?? null;
      } else {
        const v = pca.strictParse(c.raw);
        r.canon = pca.canonicalizeStrict(v);
        r.hash = pca.hashCanonical(v);
      }
    } catch (e) { r.error = (c.kind === 'canon' ? 'parse' : 'exception:') + (e as Error).message.slice(0, 60); }
    out.push(JSON.stringify(r));
  }
  writeFileSync(outp!, out.join('\n') + '\n');
}
main();
