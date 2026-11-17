// Oracle: the agent-side framework-adapter helpers of @atlasauth/pca (src/adapters.ts): messageSegments, provenanceHeaders and a
// provenance recorder fed through recordMessages / recordInput / recordPrincipal / recordToolResult (fixed key, session and clock, so the
// signed bundles are byte-deterministic). Writes out/ref-adapters.json.gz.
//   messageSegments(m)            [{origin, source, content}]
//   provenanceHeaders(bundle)     {} or {'PCA-Provenance': b64u}  (a bundle over 8192 base64url characters is left out)
//   recordFlow({steps})           {bundles: [forAction bundle per 'act' step], receipts}; steps: {op:'messages'|'input'|'principal'|'tool'|'act', ...}
import { Oracle, refWrite, seed } from './lib.mjs';

const M: any = await import('../../../packages/pca/src/index.ts');
const o = new Oracle('adapters', 'tools/pca-audit/oracles/adapters.mts', 'TS-reference oracle for the agent-side adapter helpers (message segments, provenance headers, recorder flow).');
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const SK = b64u(seed('ref-adapters/recorder'));
const SESSION = b64u(seed('ref-adapters/session'));

// ---- messageSegments ----------------------------------------------------------------------------------------------------
const msgs: any[] = [
  { role: 'user', content: 'hello' }, { role: 'User', content: 'cased' }, { role: 'human', content: 'h' }, { type: 'human', content: 'lc' }, { type: 'ai', content: 'x' },
  { role: 'assistant', content: 'a' }, { role: 'system', content: 's' }, { role: 'developer', content: 'd' }, { role: 'model', content: 'm' },
  { role: 'tool', content: 'result', tool_call_id: 'c1' }, { role: 'tool', name: 'fetch', content: { a: 1, b: [1, 2.5] } }, { role: 'function', name: 'f', content: 'x' },
  { role: 'tool' }, { role: 'weird', content: 'w' }, { content: 'norole' }, {}, { role: 5, type: 'user', content: 'r5' }, { role: 5, content: 'r5b' },
  { role: 'user' }, { role: 'user', content: null }, { role: 'user', content: 7 }, { role: 'user', content: { k: 'v' } }, { role: 'user', content: [] },
  { role: 'user', content: [{ type: 'text', text: 'one' }, { type: 'text', text: 'two' }] },
  { role: 'user', content: [{ type: 'text', text: 'q' }, { type: 'image', source: { data: 'abc' } }] },
  { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu1', content: 'out' }] },
  { role: 'user', content: [{ type: 'tool-result', toolName: 'tn', result: { r: 1 } }] },
  { role: 'user', content: [{ type: 'function_call_output', call_id: 'x', output: 'fo' }, { type: 'tool_result' }] },
  { role: 'user', content: [{ type: 'tool_result', name: 5 }, { type: 'tool_result', name: { a: 1 } }, { type: 'tool_result', name: [1, null, 'z'] }, { type: 'tool_result', name: 1.5 }, { type: 'tool_result', name: true }] },
  { role: 'user', name: 'nm', content: [{ type: 'tool_result', content: 'c' }] }, { role: 'user', tool_call_id: 'tc', content: [{ type: 'tool_result' }] },
  { role: 'user', content: [null, 5, true, 'a', [1, 2], { text: 't' }, { type: 'text', text: 5 }, { type: 7, text: 'ty' }, {}] },
  { role: 'tool', toolName: 'tn', name: 'n', tool_use_id: 'u', content: 'c' }, { role: 'tool', tool_use_id: 'u', name: 'n2' }, { role: 'tool', toolCallId: 'tcid', content: '' },
  null, 5, 'str', true, [], [1, 2], { role: 'user', content: 'é €' },
];
for (const [i, m] of msgs.entries()) await o.run('messageSegments', `m${i}`, M.messageSegments, [m]);

// ---- recorder flow ------------------------------------------------------------------------------------------------------
const flow = (a: any) => {
  const rec = M.createProvenanceRecorder({ mediator: 'harness', kid: 'k1', secretKey: new Uint8Array(Buffer.from(SK, 'base64url')), session: SESSION, now: () => 1_800_000_000_000 });
  const agent = { provenance: rec };
  const bundles: any[] = [];
  for (const st of a.steps) {
    if (st.op === 'messages') M.recordMessages(agent, st.messages);
    else if (st.op === 'input') M.recordInput(agent, st.input);
    else if (st.op === 'principal') M.recordPrincipal(agent, st.text);
    else if (st.op === 'tool') M.recordToolResult(agent, st.tool, st.output);
    else if (st.op === 'act') bundles.push(rec.forAction(st.action));
  }
  return { bundles, receipts: rec.receipts() };
};
const ACT = { op: 'act', action: { verb: 'email.send', resource: 'mail/1', params: { to: 'bob@acme.example', n: 3 } } };
const M1 = { role: 'user', content: 'Send the report to bob' };
const M2 = { role: 'assistant', content: 'ok' };
const M3 = { role: 'tool', name: 'gmail.read', content: { subject: 'Q3', body: 'text', n: 2.5 } };
const M4 = { role: 'user', content: [{ type: 'text', text: 'and cc' }, { type: 'text', text: 'alice' }, { type: 'tool_result', tool_use_id: 'tu', content: 'r' }, { type: 'image', url: 'u' }] };
const flows: [string, any[]][] = [
  ['empty', [ACT]], ['principal', [{ op: 'principal', text: 'do it' }, ACT]], ['tool', [{ op: 'tool', tool: 'search', output: { hits: [1, 2] } }, { op: 'tool', tool: 't2', output: 'plain' }, ACT]],
  ['messages', [{ op: 'messages', messages: [M1, M2, M3, M4] }, ACT]],
  ['incremental', [{ op: 'messages', messages: [M1] }, { op: 'messages', messages: [M1, M2, M3] }, { op: 'messages', messages: [M1, M2, M3] }, ACT]],
  ['restart', [{ op: 'messages', messages: [M1, M2, M3] }, { op: 'messages', messages: [M1] }, ACT]],
  ['input-string', [{ op: 'input', input: 'a string' }, ACT]], ['input-list', [{ op: 'input', input: [M1, M3] }, ACT]],
  ['input-dict', [{ op: 'input', input: { messages: [M1], input: 'i', prompt: 'p', query: 'q', question: 'qq', message: 'm', text: 't', other: 'ignored' } }, ACT]],
  ['input-nested', [{ op: 'input', input: { input: [M1, M3], text: [M4] } }, ACT]],
  ['input-nothing', [{ op: 'input', input: null }, { op: 'input', input: 5 }, { op: 'input', input: { other: 1 } }, { op: 'input', input: { prompt: 7 } }, ACT]],
  ['object-content', [{ op: 'messages', messages: [{ role: 'user', content: { b: 1, a: [1, 2.5, null, 'x'], c: { z: 1, y: 'é' } } }, { role: 'user', content: 12 }, { role: 'user', content: [{ k: 1 }, { type: 'image', n: 2 }] }] }, ACT]],
  ['two-acts', [{ op: 'principal', text: 'go' }, ACT, { op: 'tool', tool: 'x', output: 'y' }, { op: 'act', action: { verb: 'pay', resource: 'acct/9', params: {} } }]],
  ['unicode', [{ op: 'principal', text: 'héllo   €' }, { op: 'tool', tool: 'é'.repeat(200), output: '😀' }, ACT]],
];
for (const [n, steps] of flows) await o.run('recordFlow', n, flow, [{ steps }]);

// ---- provenanceHeaders --------------------------------------------------------------------------------------------------
const bundleOf = (n: number) => flow({ steps: [...Array.from({ length: n }, (_, i) => ({ op: 'tool', tool: `t${i}`, output: `out${i}` })), ACT] }).bundles[0];
const bundles: any[] = [bundleOf(0), bundleOf(1), bundleOf(8), bundleOf(15), bundleOf(16), bundleOf(17), bundleOf(40), { a: 1 }, { z: [1, 2, { y: 'é' }], a: 'x' }, {}, []];
for (const [i, b] of bundles.entries()) await o.run('provenanceHeaders', `b${i}`, M.provenanceHeaders, [b]);
await o.run('provenanceHeaders', 'strict-float', M.provenanceHeaders, [{ a: 1.5 }]);
// the exact header-size boundary: pad a plain object until its base64url form is 8191 / 8192 / 8193 characters
for (const target of [8191, 8192, 8193]) {
  let n = 0;
  const len = (k: number) => Buffer.from(JSON.stringify({ p: 'x'.repeat(k) })).toString('base64url').length;
  while (len(n) < target && n < 9000) n++;
  await o.run('provenanceHeaders', `size-${target}`, M.provenanceHeaders, [{ p: 'x'.repeat(n) }]);
}
refWrite(o, 'adapters');
