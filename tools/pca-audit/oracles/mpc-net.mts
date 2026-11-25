// Oracle: @atlasauth/pca-mpc networked-runner PURE parts (wire frame codec, canonical field hex, NetAbort, pairwise-authenticated shares,
// forensic disclosures, OT-over-network canonical codecs, gadget seed commitments). Sockets / TLS / the distributed driver are not covered.
// Big integers cross as DECIMAL STRINGS; bytes as {"$bytes": b64url}. PORTING (entry points in net.atlasauth.pca.mpc):
//   encodeFrame(frame) -> NetWire.encodeFrame (bytes)      split(chunks) -> NetWire.FrameSplitter.push over each chunk: {frames:[bytes...]} or throw
//   peekVersion/parseFrame/versionMismatch(bytes) -> NetWire.*   hx(v) / unhx(s) / unhxArray(a, len)
//   netAbort(kind, blamed, reporter, detail, claimedKind, claimedBlame, opts) -> NetWire.NetAbort (fields as listed in the case output)
//   pa(op, ...) -> NetPa.*      forensics(op, ...) -> NetForensics.*      codec(op, ...) -> NetCodec.* / gadget helpers
import * as W0 from '../../../packages/pca-mpc/src/net/wire';
import * as PA0 from '../../../packages/pca-mpc/src/net/pa';
import * as FO0 from '../../../packages/pca-mpc/src/net/forensics';
import * as ON0 from '../../../packages/pca-mpc/src/net/ot-net';
import * as GD0 from '../../../packages/pca-mpc/src/net/gadget';
import * as PR0 from '../../../packages/pca-mpc/src/net/prep';
import * as F0 from '../../../packages/pca-mpc/src/field';
import { Oracle, refWrite, rng } from './lib.mjs';
const d = (m: any) => (m as any).default ?? m;
const W: any = d(W0), PA: any = d(PA0), FO: any = d(FO0), ON: any = d(ON0), GD: any = d(GD0), PR: any = d(PR0), F: any = d(F0);

const o = new Oracle('mpc-net', 'tools/pca-audit/oracles/mpc-net.mts', 'TS-reference oracle for the pure parts of the PCA MPC networked runner.');
const r = rng(0x4e4554);
const dec = (v: any): any => typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array || Buffer.isBuffer(v) ? new Uint8Array(v) : v instanceof Map ? [...v.entries()].map(([k, x]) => [k, dec(x)]) : v instanceof Set ? [...v].sort().map(dec) : Array.isArray(v) ? v.map(dec) : v !== null && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, dec(x)])) : v;
const D = (f: (...a: any[]) => any) => (...a: any[]) => dec(f(...a));
const B = (s: any) => BigInt(s);
const bb = (s: string) => ({ $bytes: Buffer.from(s, 'utf8').toString('base64url') });
const u8 = (a: any): Buffer => Buffer.from(a.$bytes, 'base64url');
const PRIME = F.PRIME;
const S = (b: bigint) => b.toString();

// ---- frames
const fr = (v: any, ty: any, sid: any, seq: any, rd: any, dd: any) => ({ v, ty, sid, seq, rd, d: dd });
const frames: any[] = [fr(2, 'hello', 'sess', 0, 'r', null), fr(2, 'msg', 'sid-é', 5, 'round/1', { a: [1, 2, 'x'], b: { c: null } }), fr(2, 'abort', '', 4294967296, 'x', 'he said "hi"\n\t\u0001 '),
  fr(2, 'msg', 's', 1, 'r', ['0', 'ff', 'abc']), fr(3, 'msg', 's', 1, 'r', 1.5), fr(2, 'msg', 's', 9007199254740991, 'r', -1e21), fr(2, 'msg', 's', 1, 'r', 0)];
for (const [i, f] of frames.entries()) await o.run('encodeFrame', `${i}`, D((x: any) => W.encodeFrame(x)), [f]);
const bodies = (fs: any[]) => fs.map((f) => Buffer.from(JSON.stringify(f), 'utf8'));
const goodBody = (x: any) => Buffer.from(JSON.stringify(x), 'utf8').toString('base64url');
const enc = (f: any) => W.encodeFrame(f);
const streams: Array<[string, Buffer, number[]]> = [];
const all = Buffer.concat(frames.slice(0, 4).map(enc));
streams.push(['whole', all, [all.length]], ['byte-by-byte', all, Array.from({ length: all.length }, () => 1)], ['uneven', all, [3, 7, 1, 20, 100, 5, 4000]]);
streams.push(['empty-frame', Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]), [8]], ['partial-header', Buffer.from([0, 0]), [2]], ['partial-body', Buffer.from([0, 0, 0, 5, 1, 2]), [6]]);
streams.push(['oversize', Buffer.from([0, 0x40, 0, 1, 9, 9]), [6]], ['at-limit-prefix', Buffer.from([0, 0x40, 0, 0]), [4]], ['huge-prefix', Buffer.from([0xff, 0xff, 0xff, 0xff]), [4]]);
streams.push(['two-then-partial', Buffer.concat([enc(frames[0]), enc(frames[1]), Buffer.from([0, 0, 1, 0, 7])]), [1000]]);
for (const [name, buf, cuts] of streams) {
  const chunks: Buffer[] = []; let at = 0;
  for (const c of cuts) { if (at >= buf.length) break; chunks.push(buf.subarray(at, at + c)); at += c; }
  if (at < buf.length) chunks.push(buf.subarray(at));
  await o.run('split', name, D((cs: any[]) => { const s = new W.FrameSplitter(); const out: any[] = []; for (const c of cs) out.push(...s.push(u8(c))); return { frames: out }; }), [chunks.map((c) => ({ $bytes: c.toString('base64url') }))]);
}
// envelope validation
const base = { v: 2, ty: 'msg', sid: 's', seq: 3, rd: 'r', d: [1] };
const envs: Array<[string, any]> = [['ok', base], ['v1', { ...base, v: 1 }], ['v3', { ...base, v: 3 }], ['v2.0', { ...base, v: 2.0 }], ['vstr', { ...base, v: '2' }], ['v-null', { ...base, v: null }], ['no-v', { ty: 'msg', sid: 's', seq: 3, rd: 'r', d: 1, z: 0 }],
  ['extra', { ...base, extra: 1 }], ['missing-d', { v: 2, ty: 'msg', sid: 's', seq: 3, rd: 'r', x: 1 }], ['d-null', { ...base, d: null }], ['ty-bad', { ...base, ty: 'bogus' }], ['ty-num', { ...base, ty: 1 }], ['sid-num', { ...base, sid: 1 }], ['rd-num', { ...base, rd: 1 }],
  ['seq-neg', { ...base, seq: -1 }], ['seq-frac', { ...base, seq: 1.5 }], ['seq-big', { ...base, seq: 2 ** 53 }], ['seq-max', { ...base, seq: 2 ** 53 - 1 }], ['seq-str', { ...base, seq: '1' }], ['hello', { ...base, ty: 'hello' }], ['abort', { ...base, ty: 'abort' }], ['v-big', { ...base, v: 2 ** 53 }]];
for (const [n, e] of envs) {
  await o.run('peekVersion', n, D((b: any) => W.peekVersion(u8(b))), [{ $bytes: goodBody(e) }]);
  await o.run('parseFrame', n, D((b: any) => W.parseFrame(u8(b))), [{ $bytes: goodBody(e) }]);
  await o.run('versionMismatch', n, D((b: any) => W.versionMismatch(u8(b))), [{ $bytes: goodBody(e) }]);
}
const raws: Array<[string, string]> = [['negzero-v', '{"v":-0,"ty":"msg","sid":"s","seq":0,"rd":"r","d":1}'], ['negzero-seq', '{"v":2,"ty":"msg","sid":"s","seq":-0,"rd":"r","d":1}'], ['negzero-seq3', '{"v":3,"ty":"msg","sid":"s","seq":-0,"rd":"r","d":1}'],
  ['exp-v', '{"v":2e0,"ty":"msg","sid":"s","seq":0,"rd":"r","d":1}'], ['array', '[1,2]'], ['scalar', '3'], ['null', 'null'], ['garbage', 'not json'], ['empty', ''], ['trailing', '{"v":2} x'], ['dup-key', '{"v":1,"v":2,"ty":"msg","sid":"s","seq":0,"rd":"r","d":1}']];
for (const [n, t] of raws) {
  const b = { $bytes: Buffer.from(t, 'utf8').toString('base64url') };
  await o.run('peekVersion', `raw-${n}`, D((x: any) => W.peekVersion(u8(x))), [b]);
  await o.run('parseFrame', `raw-${n}`, D((x: any) => W.parseFrame(u8(x))), [b]);
  await o.run('versionMismatch', `raw-${n}`, D((x: any) => W.versionMismatch(u8(x))), [b]);
}
// hex
for (const v of ['0', '1', '255', '4096', S(PRIME - 1n), S(PRIME), S(PRIME + 1n), '-1', S(1n << 64n)]) await o.run('hx', v, D((x: string) => W.hx(B(x))), [v]);
for (const [ui, s] of ['0', '1', 'ff', 'FF', '00', '0f', '', ' 1', '1 ', 'g', '1fffffffffffff', S(0n) && PRIME.toString(16), (PRIME - 1n).toString(16), '1'.repeat(16), '1'.repeat(17), 'f'.repeat(16), null, 5, '+1', '-1', '0x1'].entries() as any) {
  await o.run('unhx', `${ui}`, D((x: any) => W.unhx(x)), [s]);
}
for (const [a, n] of [[['0', '1'], 2], [['0', '1'], 3], [[], 0], [['0', '01'], 2], [['ff'], 1], ['x', 1], [null, 0], [[PRIME.toString(16)], 1]] as any[]) await o.run('unhxArray', JSON.stringify(a).slice(0, 40) + '/' + n, D((x: any, l: number) => W.unhxArray(x, l)), [a, n]);
// NetAbort
const na = (kind: string, blamed: any, rep: number, detail: string, ck: any, cb: any, opts: any) => {
  const e = new W.NetAbort(kind, blamed, rep, detail, ck ?? undefined, cb === 'U' ? undefined : cb, opts ?? undefined);
  return { message: e.message, name: e.name, kind: e.kind, blamed: e.blamed, reporter: e.reporter, reason: e.reason, claimedKind: e.claimedKind ?? null, claimedBlame: e.claimedBlame ?? null, evidence: e.evidence ?? null, deadlineMs: e.deadlineMs ?? null };
};
for (const [k, bl, rep, det, ck, cb, op] of [['timeout', 2, 0, 'late', null, 'U', null], ['mac-check', null, 1, 'x', null, 'U', null], ['mac-check', null, 1, 'x', 'dealer', 3, { reason: 'because' }], ['local', null, 0, '', null, 'U', { reason: '' }],
  ['peer-abort', 0, 2, 'd', 'timeout', null, { evidence: { a: 1 }, deadlineMs: 500 }], ['version', 1, 1, 'v', null, 'U', { evidence: null, deadlineMs: 0 }], ['ot-check', null, 3, 'résumé', null, 'U', { reason: 'r' }]] as any[]) {
  await o.run('netAbort', `${k}/${bl}/${rep}/${String(ck)}/${cb}/${JSON.stringify(op)}`.slice(0, 80), D(na), [k, bl, rep, det, ck, cb, op]);
}
await o.run('abortKinds', 'set', D(() => [...W.ABORT_KINDS].sort()), []);

// ---- pairwise-authenticated shares
const rn = () => S(BigInt(r.int(0, 2 ** 31)) * (1n << 30n) + BigInt(r.int(0, 2 ** 30)));
const mkPA = (n: number) => ({ x: rn(), tag: Array.from({ length: n }, rn), key: Array.from({ length: n }, rn) });
const toPA = (p: any) => ({ x: B(p.x), tag: p.tag.map(B), key: p.key.map(B) });
const mkAW = (n: number, keys: number) => ({ v: mkPA(n), m: Array.from({ length: keys }, () => mkPA(n)) });
const toAW = (a: any) => ({ v: toPA(a.v), m: a.m.map(toPA) });
for (const n of [2, 3, 4]) {
  const a = mkPA(n), b = mkPA(n);
  for (const op of ['add', 'sub']) await o.run('pa', `${op}/${n}`, D((oo: string, x: any, y: any) => (oo === 'add' ? PA.paAdd : PA.paSub)(toPA(x), toPA(y))), [op, a, b]);
  await o.run('pa', `neg/${n}`, D((oo: string, x: any) => PA.paNeg(toPA(x))), ['neg', a]);
  for (const c of ['0', '1', S(PRIME - 1n), rn()]) await o.run('pa', `scale/${n}/${c}`.slice(0, 60), D((oo: string, x: any, cc: string) => PA.paScale(toPA(x), B(cc))), ['scale', a, c]);
  for (const [id, tagged] of [[0, true], [1, true], [1, false], [0, false]] as const) {
    await o.run('pa', `addPublic0/${n}/${id}/${tagged}`, D((oo: string, x: any, i: number, dl: string, tg: boolean, c: string) => PA.paAddPublic0({ id: i, n, delta: B(dl), tagged: tg }, toPA(x), B(c))), ['addPublic0', a, id, rn(), tagged, rn()]);
    const x = rn(), tag = rn();
    await o.run('pa', `verify/${n}/${id}/${tagged}`, D((oo: string, p: any, i: number, dl: string, from: number, xx: string, tg: string) => PA.paVerify({ id: i, n, delta: B(dl), tagged: true }, toPA(p), from, B(xx), B(tg))), ['verify', a, id, rn(), (id + 1) % n, x, tag]);
    const dl = B(rn()); const key = B(a.key[1 % n]); const good = F.fadd(key, F.fmul(dl, B(x)));
    await o.run('pa', `verifyGood/${n}/${id}/${tagged}`, D((oo: string, p: any, i: number, dl2: string, from: number, xx: string, tg: string) => PA.paVerify({ id: i, n, delta: B(dl2), tagged: true }, toPA(p), from, B(xx), B(tg))), ['verify', a, id, S(dl), 1 % n, x, S(good)]);
    const flat = PA.paFlat(toPA(a), id, n, tagged);
    await o.run('pa', `flat/${n}/${id}/${tagged}`, D((oo: string, p: any, i: number, tg: boolean) => { const f = PA.paFlat(toPA(p), i, n, tg); return { f, w: PA.paWidth(n, tg), back: PA.paParse(f, 0, i, n, tg) }; }), ['flat', a, id, tagged]);
    void flat;
  }
  for (const keys of [1, 2]) for (const tagged of [true, false]) {
    const aw = mkAW(n, keys), aw2 = mkAW(n, keys);
    const alpha = Array.from({ length: keys }, () => mkPA(n));
    await o.run('aw', `ops/${n}/${keys}/${tagged}`, D((x: any, y: any, al: any, tg: boolean, c: string) => ({
      add: PA.wAdd(toAW(x), toAW(y)), sub: PA.wSub(toAW(x), toAW(y)), neg: PA.wNeg(toAW(x)), scale: PA.wScale(toAW(x), B(c)),
      addPublic: PA.wAddPublic({ id: 1, n, delta: 7n, tagged: tg }, toAW(x), B(c), al.map(toPA)), addPublic0: PA.wAddPublic({ id: 0, n, delta: 7n, tagged: tg }, toAW(x), B(c), al.map(toPA)),
    })), [aw, aw2, alpha, tagged, rn()]);
    await o.run('aw', `flat/${n}/${keys}/${tagged}`, D((x: any, id: number, tg: boolean) => { const f = PA.awFlat(toAW(x), id, n, tg); return { f, w: PA.awWidth(n, keys, tg), back: PA.awParse(f, 0, id, n, keys, tg) }; }), [aw, n - 1, tagged]);
  }
}
await o.run('aw', 'sharingsPerTriple', D((p: number) => PR.sharingsPerTriple(p)), [2]);

// ---- forensics
const hxs = (x: bigint) => x.toString(16);
const slotW = (rows: number, peers: number[], tamper?: string) => ({
  bits: Array.from({ length: rows }, () => r.int(0, 1)).join(''), y: hxs(BigInt(r.int(0, 1e9))), z: hxs(BigInt(r.int(0, 1e9))),
  recv: peers.map((p) => [p, Array.from({ length: rows }, () => hxs(BigInt(r.int(0, 1e9))))]), rho: peers.map((p) => [p, Array.from({ length: rows }, () => hxs(BigInt(r.int(0, 1e9))))]),
});
const rows = 5, peers = [1, 2];
const good = Array.from({ length: 2 }, () => slotW(rows, peers));
const encD = (x: any) => dec(x);
await o.run('forensics', 'parse/ok', D((raw: any, sl: number, rw: number, ps: number[]) => { const dd = FO.parseDisclosure(raw, sl, rw, ps); return { dd: encD(dd), back: FO.wireDisclosure(dd) }; }), [good, 2, rows, peers]);
const mut = (f: (x: any) => void) => { const c = JSON.parse(JSON.stringify(good)); f(c); return c; };
const badCases: Array<[string, any, number, number, number[]]> = [['slots', good, 3, rows, peers], ['rows', good, 2, rows + 1, peers], ['peers-len', good, 2, rows, [1]], ['not-array', { a: 1 }, 2, rows, peers],
  ['bits-chars', mut((c) => { c[0].bits = '0000x'; }), 2, rows, peers], ['bits-type', mut((c) => { c[0].bits = 5; }), 2, rows, peers], ['y-bad', mut((c) => { c[1].y = '01'; }), 2, rows, peers],
  ['z-big', mut((c) => { c[0].z = PRIME.toString(16); }), 2, rows, peers], ['peer-unknown', mut((c) => { c[0].recv[0][0] = 9; }), 2, rows, peers], ['peer-dup', mut((c) => { c[0].rho[1][0] = 1; }), 2, rows, peers],
  ['peer-str', mut((c) => { c[0].recv[0][0] = '1'; }), 2, rows, peers], ['peer-frac', mut((c) => { c[0].recv[0][0] = 1.5; }), 2, rows, peers], ['row-len', mut((c) => { c[0].recv[0][1].pop(); }), 2, rows, peers],
  ['row-elem', mut((c) => { c[0].rho[0][1][2] = 'zz'; }), 2, rows, peers], ['entry-shape', mut((c) => { c[0].recv[0] = [1]; }), 2, rows, peers], ['slot-null', mut((c) => { c[1] = null; }), 2, rows, peers], ['slot-array', mut((c) => { c[1] = []; }), 2, rows, peers]];
for (const [n, raw, sl, rw, ps] of badCases) await o.run('forensics', `parse/${n}`, D((raw2: any, s2: number, r2: number, p2: number[]) => FO.parseDisclosure(raw2, s2, r2, p2)), [raw, sl, rw, ps]);
// audit: build a consistent 3-party disclosure set from a gadget
const gadget = Array.from({ length: 6 }, () => BigInt(r.int(1, 1e9)));
const mkAudit = (cheat: string | null) => {
  const n = 3, slots = 2, rowsA = gadget.length;
  const bits = Array.from({ length: n }, () => Array.from({ length: slots }, () => Array.from({ length: rowsA }, () => r.int(0, 1))));
  const y = Array.from({ length: n }, () => Array.from({ length: slots }, () => BigInt(r.int(0, 1e9))));
  const rho: bigint[][][][] = Array.from({ length: n }, () => Array.from({ length: n }, () => Array.from({ length: slots }, () => Array.from({ length: rowsA }, () => BigInt(r.int(0, 1e9))))));
  const out: any = {};
  for (let i = 0; i < n; i++) out[i] = Array.from({ length: slots }, (_, s) => {
    let value = 0n; for (let k = 0; k < rowsA; k++) if (bits[i]![s]![k] === 1) value += gadget[k]!;
    const recv = new Map<number, bigint[]>(), rh = new Map<number, bigint[]>();
    let implied = F.fmul(F.mod(value), y[i]![s]!);
    for (let p = 0; p < n; p++) {
      if (p === i) continue;
      const got = Array.from({ length: rowsA }, (_, k) => F.fadd(rho[p]![i]![s]![k]!, bits[i]![s]![k] === 1 ? F.fmul(gadget[k]!, F.mod(y[p]![s]!)) : 0n));
      recv.set(p, got); rh.set(p, rho[i]![p]![s]!);
      for (const v of got) implied = F.fadd(implied, F.mod(v));
      for (const v of rho[i]![p]![s]!) implied = F.fsub(implied, v);
    }
    return { bits: bits[i]![s]!, y: y[i]![s]!, z: implied, recv, rho: rh };
  });
  if (cheat === 'self') out[1][0].z = F.fadd(out[1][0].z, 1n);
  if (cheat === 'pair') out[2][1].recv.get(0)[3] = F.fadd(out[2][1].recv.get(0)[3], 1n);
  if (cheat === 'both') { out[0][0].z = F.fadd(out[0][0].z, 1n); out[2][1].recv.get(1)[0] = F.fadd(out[2][1].recv.get(1)[0], 5n); }
  return out;
};
const toDis = (x: any) => x.map((s: any) => ({ bits: s.bits, y: B(s.y), z: B(s.z), recv: new Map(s.recv.map(([p, v]: any) => [p, v.map(B)])), rho: new Map(s.rho.map(([p, v]: any) => [p, v.map(B)])) }));
const auditW = D((a: any, g: string[], drop: number | null) => {
  const m = new Map<number, any>(Object.entries(a).map(([k, v]: any) => [Number(k), toDis(v)]));
  if (drop !== null) m.delete(drop);
  const res = FO.auditDisclosures(m, g.map(B));
  return { selfBad: [...res.selfBad].sort(), pairBad: res.pairBad, blame: [0, 1, 2].map((me) => FO.blameFrom(me, res)) };
});
for (const cheat of [null, 'self', 'pair', 'both']) await o.run('forensics', `audit/${cheat}`, auditW, [dec(mkAudit(cheat)), gadget.map(S), null]);
await o.run('forensics', 'audit/missing-party', auditW, [dec(mkAudit(null)), gadget.map(S), 2]);
await o.run('forensics', 'audit/missing-party0', auditW, [dec(mkAudit('pair')), gadget.map(S), 0]);
for (const [me, selfBad, pairBad] of [[0, [1, 2], []], [0, [0], []], [1, [], [[0, 1], [2, 1]]], [2, [], [[0, 1], [2, 1]]], [0, [], []], [1, [], [[1, 0]]]] as const) {
  await o.run('forensics', `blame/${me}/${JSON.stringify(selfBad)}/${JSON.stringify(pairBad)}`, D((m: number, sb: number[], pb: number[][]) => FO.blameFrom(m, { selfBad: new Set(sb), pairBad: pb })), [me, selfBad, pairBad]);
}
await o.run('forensics', 'commit', D((sid: string, p: number, t: number, dl: number, nonce: string, wire: any) => FO.disclosureCommit(sid, p, t, dl, nonce, wire)), ['s-é', 2, 7, 30000, 'ab'.repeat(32), FO.wireDisclosure(toDis(dec(mkAudit(null))[0]))]);
await o.run('forensics', 'commit-scalar', D((sid: string, p: number, t: number, dl: number, nonce: string, wire: any) => FO.disclosureCommit(sid, p, t, dl, nonce, wire)), ['s', 0, 0, 0, '00', null]);
await o.run('forensics', 'slotsFor', D((p: number) => FO.slotsFor(p)), [3]);

// ---- ot-net codec / gadget
const b64s = ['', 'AQIDBA==', 'AQIDBB==', 'AQIDBA', 'AQID', 'AQI=', 'AQJ=', 'AA==', '/+8=', '_-8=', 'AQ=A', '====', 'A', 'AAAA=', 'AQIDBA===', 'ab c', 'AQI', 'AQI==', 'YQ==', 'YR==', 'YWI=', 'YWJ='];
for (const [bi, s] of b64s.entries()) {
  await o.run('codec', `unb64/${bi}`, D((op: string, x: any, len: any) => ON.unb64(x, len ?? undefined)), ['unb64', s, null]);
}
await o.run('codec', 'unb64/len-ok', D((op: string, x: any, len: any) => ON.unb64(x, len ?? undefined)), ['unb64', 'AQIDBA==', 4]);
await o.run('codec', 'unb64/len-bad', D((op: string, x: any, len: any) => ON.unb64(x, len ?? undefined)), ['unb64', 'AQIDBA==', 5]);
await o.run('codec', 'unb64/nonstring', D((op: string, x: any, len: any) => ON.unb64(x, len ?? undefined)), ['unb64', 5, null]);
await o.run('codec', 'b64', D((op: string, b: any) => ON.b64(u8(b))), ['b64', bb('hello?>>')]);
const Q = (1n << 255n) - 19n;
for (const [hi, s] of ['0', '1', 'ff', '00', '0f', 'FF', '', ' 1', 'g', Q.toString(16), (Q - 1n).toString(16), (Q + 1n).toString(16), 'f'.repeat(64), 'f'.repeat(65), '1' + '0'.repeat(63), null, 7].entries() as any) {
  await o.run('codec', `hexBig/${hi}`, D((op: string, x: any) => ON.hexBig(x)), ['hexBig', s]);
}
const M0 = d(await import('../../../packages/pca-mpc/src/ec'));
const gp = (k: bigint) => { const a = M0.toAffine(M0.mulBase(k)); return { x: a.x.toString(16), y: a.y.toString(16) }; };
for (const [n, v] of [['ok', gp(5n)], ['ok2', gp(123456789n)], ['identity', { x: '0', y: '1' }], ['order2', { x: '0', y: (Q - 1n).toString(16) }], ['offcurve', { x: '5', y: '7' }], ['bad-x', { x: '05', y: '1' }], ['missing', { x: '1' }], ['null', null], ['array', [1, 2]], ['x-big', { x: Q.toString(16), y: '1' }]] as any[]) {
  await o.run('codec', `jPt/${n}`, D((op: string, x: any) => { const p = ON.jPt(x); return ON.ptJ(p); }), ['jPt', v]);
}
await o.run('codec', 'ptJ', D((op: string, k: string) => ON.ptJ(M0.mulBase(B(k)))), ['ptJ', '77']);
for (const [sid, p, seedS] of [['s', 0, 'seed'], ['sess-é', 12, 'x'.repeat(32)], ['', 3, '']] as const) {
  await o.run('codec', `gadgetCommit/${p}`, D((op: string, s: string, pp: number, sd: any) => GD.gadgetCommit(s, pp, u8(sd))), ['gadgetCommit', sid, p, bb(seedS)]);
  for (const rd of ['gd-c', 'gd-o']) await o.run('codec', `gadgetStatement/${p}/${rd}`, D((op: string, s: string, rr: string, sg: number, v: string) => GD.gadgetStatement(s, rr, sg, v)), ['gadgetStatement', sid, rd, p, 'val"ue\n']);
}

for (const c of o.cases) if (JSON.stringify(c.out).includes('is not a function') || JSON.stringify(c.out).includes('undefined')) throw new Error('generator bug in ' + c.name + ': ' + JSON.stringify(c.out).slice(0, 300));
refWrite(o, 'mpc-net');
