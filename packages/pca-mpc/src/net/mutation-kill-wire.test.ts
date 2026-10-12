import { describe, expect, it } from 'vitest';
import { PRIME } from '../field';
import { ABORT_KINDS, FrameSplitter, MAX_FRAME_BYTES, NetAbort, WIRE_VERSION, encodeFrame, hx, parseFrame, peekVersion, unhx, unhxArray, type Frame } from './wire';

const frame = (over: Partial<Frame> = {}): Frame => ({ v: WIRE_VERSION, ty: 'msg', sid: 's', seq: 0, rd: 'r', d: null, ...over });
const body = (o: unknown): Buffer => Buffer.from(JSON.stringify(o), 'utf8');

describe('NetAbort', () => {
  it('formats the message with blamed party or "none", reporter and detail', () => {
    expect(new NetAbort('timeout', 2, 1, 'late').message).toBe('[timeout] blamed=2 reporter=1: late');
    expect(new NetAbort('timeout', 0, 1, 'late').message).toBe('[timeout] blamed=0 reporter=1: late');
    expect(new NetAbort('mac-check', null, 3, 'bad').message).toBe('[mac-check] blamed=none reporter=3: bad');
  });
  it('is named NetAbort and carries kind/blamed/reporter', () => {
    const e = new NetAbort('dealer', 4, 5, 'x');
    expect(e.name).toBe('NetAbort');
    expect(e.kind).toBe('dealer');
    expect(e.blamed).toBe(4);
    expect(e.reporter).toBe(5);
  });
  it('reason is null when a party is blamed, even if a reason is passed', () => {
    expect(new NetAbort('timeout', 1, 0, 'x', undefined, undefined, { reason: 'because' }).reason).toBeNull();
  });
  it('reason: explicit non-empty reason kept; missing or empty reason gets the unattributable default', () => {
    const dflt = 'unattributable: the evidence available to this party does not identify a culprit';
    expect(new NetAbort('mac-check', null, 0, 'x', undefined, undefined, { reason: 'my reason' }).reason).toBe('my reason');
    expect(new NetAbort('mac-check', null, 0, 'x', undefined, undefined, { reason: '' }).reason).toBe(dflt);
    expect(new NetAbort('mac-check', null, 0, 'x').reason).toBe(dflt);
  });
  it('evidence and deadlineMs are carried when supplied (including falsy values)', () => {
    const bare = new NetAbort('timeout', 1, 0, 'x');
    expect(bare.evidence).toBeUndefined();
    expect(bare.deadlineMs).toBeUndefined();
    const full = new NetAbort('timeout', 1, 0, 'x', undefined, undefined, { evidence: 0, deadlineMs: 0 });
    expect(full.evidence).toBe(0);
    expect(full.deadlineMs).toBe(0);
    const ev = { a: 1 };
    expect(new NetAbort('equivocation', 1, 0, 'x', undefined, undefined, { evidence: ev, deadlineMs: 250 })).toMatchObject({ evidence: ev, deadlineMs: 250 });
  });
  it('keeps claimedKind and claimedBlame', () => {
    const e = new NetAbort('peer-abort', 2, 0, 'x', 'timeout', 7);
    expect(e.claimedKind).toBe('timeout');
    expect(e.claimedBlame).toBe(7);
  });
  it('ABORT_KINDS lists exactly the 18 kinds', () => {
    expect([...ABORT_KINDS].sort()).toEqual(
      ['commitment', 'dealer', 'disconnect', 'duplicate', 'equivocation', 'flood', 'identity', 'local', 'mac-check', 'malformed', 'oversize', 'ot-check', 'out-of-order', 'peer-abort', 'timeout', 'version', 'wrong-round', 'wrong-session'].sort(),
    );
  });
});

describe('encodeFrame', () => {
  it('length-prefixes a utf8 JSON body (multi-byte characters counted in bytes)', () => {
    const f = frame({ d: 'é€😀' });
    const out = encodeFrame(f);
    const b = Buffer.from(JSON.stringify(f), 'utf8');
    expect(out.readUInt32BE(0)).toBe(b.length);
    expect(b.length).toBeGreaterThan(JSON.stringify(f).length);
    expect(out.subarray(4).equals(b)).toBe(true);
    expect(out.length).toBe(4 + b.length);
  });
  it('accepts a body of exactly MAX_FRAME_BYTES and rejects one byte more', () => {
    const base = Buffer.byteLength(JSON.stringify(frame({ d: '' })));
    const exact = frame({ d: 'a'.repeat(MAX_FRAME_BYTES - base) });
    expect(Buffer.byteLength(JSON.stringify(exact))).toBe(MAX_FRAME_BYTES);
    expect(encodeFrame(exact).readUInt32BE(0)).toBe(MAX_FRAME_BYTES);
    expect(() => encodeFrame(frame({ d: 'a'.repeat(MAX_FRAME_BYTES - base + 1) }))).toThrow('frame too large');
  });
});

describe('FrameSplitter', () => {
  const wire = (...fs: Frame[]) => Buffer.concat(fs.map(encodeFrame));
  it('splits several frames from one chunk and from byte-at-a-time chunks identically', () => {
    const a = frame({ seq: 1, d: 'x' }), b = frame({ seq: 2, d: 'yy' });
    const all = wire(a, b);
    const one = new FrameSplitter().push(all).map((x) => JSON.parse(x.toString('utf8')));
    expect(one).toEqual([a, b]);
    const s = new FrameSplitter();
    const got: Buffer[] = [];
    for (let i = 0; i < all.length; i++) got.push(...s.push(all.subarray(i, i + 1)));
    expect(got.map((x) => JSON.parse(x.toString('utf8')))).toEqual([a, b]);
  });
  it('empty chunks are ignored (not queued) and a partial frame yields nothing', () => {
    const s = new FrameSplitter();
    const all = wire(frame({ d: 'abc' }));
    expect(s.push(Buffer.alloc(0))).toEqual([]);
    expect((s as unknown as { chunks: Buffer[] }).chunks.length).toBe(0);
    expect(s.push(all.subarray(0, 3))).toEqual([]);
    expect(s.push(Buffer.alloc(0))).toEqual([]);
    expect((s as unknown as { chunks: Buffer[] }).chunks.length).toBe(1);
    expect(s.push(all.subarray(3, all.length - 1))).toEqual([]);
    const out = s.push(all.subarray(all.length - 1));
    expect(out.length).toBe(1);
    expect(out[0]!.equals(all.subarray(4))).toBe(true);
  });
  it('a frame lying wholly in one chunk is returned as a view of it (zero-copy), a split one as a fresh copy', () => {
    const all = wire(frame({ d: 'zzz' }));
    const copy = Buffer.from(all);
    const s = new FrameSplitter();
    const [one] = s.push(all);
    all.fill(0x41, 4);
    expect(one!.every((c) => c === 0x41)).toBe(true);
    const s2 = new FrameSplitter();
    s2.push(copy.subarray(0, 10));
    const [two] = s2.push(copy.subarray(10));
    const snap = Buffer.from(two!);
    copy.fill(0x42);
    expect(two!.equals(snap)).toBe(true);
  });
  it('drops consumed chunks (no unbounded growth) and handles a frame ending exactly at a chunk boundary', () => {
    const s = new FrameSplitter();
    const a = wire(frame({ seq: 1 })), b = wire(frame({ seq: 2 }));
    expect(s.push(a).length).toBe(1);
    expect((s as unknown as { chunks: Buffer[] }).chunks.length).toBe(0);
    expect((s as unknown as { head: number }).head).toBe(0);
    s.push(b.subarray(0, 2));
    s.push(b.subarray(2, 6));
    expect((s as unknown as { chunks: Buffer[] }).chunks.length).toBe(2);
    const out = s.push(b.subarray(6));
    expect(out.length).toBe(1);
    expect(JSON.parse(out[0]!.toString('utf8')).seq).toBe(2);
    expect((s as unknown as { chunks: Buffer[] }).chunks.length).toBe(0);
  });
  it('after a frame ends mid-chunk the remainder stays queued with the right offset', () => {
    const s = new FrameSplitter();
    const a = wire(frame({ seq: 1 })), b = wire(frame({ seq: 2, d: 'tail' }));
    const out = s.push(Buffer.concat([a, b.subarray(0, 7)]));
    expect(out.length).toBe(1);
    expect((s as unknown as { chunks: Buffer[] }).chunks.length).toBe(1);
    expect((s as unknown as { head: number }).head).toBe(a.length);
    const out2 = s.push(b.subarray(7));
    expect(JSON.parse(out2[0]!.toString('utf8'))).toMatchObject({ seq: 2, d: 'tail' });
  });
  it('a zero-length body frame is returned as an empty buffer', () => {
    const s = new FrameSplitter();
    const out = s.push(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]));
    expect(out.length).toBe(2);
    expect(out[0]!.length).toBe(0);
    expect(out[1]!.length).toBe(0);
  });
  it('rejects a length prefix above MAX_FRAME_BYTES but accepts exactly MAX_FRAME_BYTES (waits for body)', () => {
    const over = Buffer.alloc(4);
    over.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
    expect(() => new FrameSplitter().push(over)).toThrow('oversize');
    const at = Buffer.alloc(4);
    at.writeUInt32BE(MAX_FRAME_BYTES, 0);
    expect(new FrameSplitter().push(at)).toEqual([]);
  });
  it('the length prefix may itself be split across chunks (high byte first)', () => {
    const s = new FrameSplitter();
    expect(s.push(Buffer.from([0x00]))).toEqual([]);
    expect(s.push(Buffer.from([0x00, 0x00]))).toEqual([]);
    expect(s.push(Buffer.from([0x02, 0x41]))).toEqual([]);
    const out = s.push(Buffer.from([0x42]));
    expect(out.map((b) => b.toString())).toEqual(['AB']);
  });
});

describe('parseFrame', () => {
  it('accepts a well-formed frame of every type', () => {
    for (const ty of ['hello', 'msg', 'abort'] as const) expect(parseFrame(body(frame({ ty })))).toEqual(frame({ ty }));
    expect(parseFrame(body(frame({ seq: Number.MAX_SAFE_INTEGER, d: { x: [1] } })))).toMatchObject({ seq: Number.MAX_SAFE_INTEGER });
    expect(parseFrame(body(frame({ seq: 0, sid: '', rd: '' })))).not.toBeNull();
  });
  it('rejects non-JSON, non-objects and null (without throwing)', () => {
    expect(parseFrame(Buffer.from('{nope'))).toBeNull();
    expect(parseFrame(Buffer.from('null'))).toBeNull();
    expect(parseFrame(Buffer.from('[]'))).toBeNull();
    expect(parseFrame(Buffer.from('"abcdef"'))).toBeNull();
    expect(parseFrame(Buffer.from('7'))).toBeNull();
    expect(parseFrame(body([1, 2, 3, 4, 5, 6]))).toBeNull();
  });
  it('rejects wrong key count (extra and missing), wrong version, bad type', () => {
    expect(parseFrame(body({ ...frame(), extra: 1 }))).toBeNull();
    const { d: _d, ...five } = frame();
    expect(parseFrame(body(five))).toBeNull();
    expect(parseFrame(body(frame({ v: WIRE_VERSION + 1 })))).toBeNull();
    expect(parseFrame(body(frame({ v: String(WIRE_VERSION) as unknown as number })))).toBeNull();
    expect(parseFrame(body(frame({ ty: 'nope' as never })))).toBeNull();
    expect(parseFrame(body(frame({ ty: 5 as never })))).toBeNull();
  });
  it('requires string sid AND string rd, a safe non-negative integer seq, and a "d" key', () => {
    expect(parseFrame(body(frame({ sid: 1 as never })))).toBeNull();
    expect(parseFrame(body(frame({ rd: 1 as never })))).toBeNull();
    expect(parseFrame(body(frame({ sid: 1 as never, rd: 2 as never })))).toBeNull();
    expect(parseFrame(body(frame({ seq: '1' as never })))).toBeNull();
    expect(parseFrame(body(frame({ seq: -1 })))).toBeNull();
    expect(parseFrame(body(frame({ seq: 1.5 })))).toBeNull();
    expect(parseFrame(body(frame({ seq: 2 ** 53 })))).toBeNull();
    const { d: _d, ...five } = frame();
    expect(parseFrame(body({ ...five, x: 0 }))).toBeNull();
  });
});

describe('peekVersion', () => {
  it('returns the integer v of an object body and null otherwise', () => {
    expect(peekVersion(body({ v: 7 }))).toBe(7);
    expect(peekVersion(body({ v: 0 }))).toBe(0);
    expect(peekVersion(body({ v: -3 }))).toBe(-3);
    expect(peekVersion(body({ v: 1.5 }))).toBeNull();
    expect(peekVersion(body({ v: 2 ** 53 }))).toBeNull();
    expect(peekVersion(body({ v: '1' }))).toBeNull();
    expect(peekVersion(body({}))).toBeNull();
    expect(peekVersion(body(null))).toBeNull();
    expect(peekVersion(body([1]))).toBeNull();
    expect(peekVersion(body(5))).toBeNull();
    expect(peekVersion(body('v'))).toBeNull();
    expect(peekVersion(Buffer.from('{broken'))).toBeNull();
  });
});

describe('field-element codec', () => {
  it('hx/unhx roundtrip canonical lowercase hex strictly below the prime', () => {
    expect(hx(0n)).toBe('0');
    expect(hx(255n)).toBe('ff');
    expect(unhx('0')).toBe(0n);
    expect(unhx('ff')).toBe(255n);
    expect(unhx(hx(PRIME - 1n))).toBe(PRIME - 1n);
    expect(unhx(hx(PRIME))).toBeNull();
    expect(unhx('00')).toBeNull();
    expect(unhx('0f')).toBeNull();
    expect(unhx('FF')).toBeNull();
    expect(unhx('')).toBeNull();
    expect(unhx('g')).toBeNull();
    expect(unhx('1'.repeat(17))).toBeNull();
    expect(unhx(5)).toBeNull();
    expect(unhx(null)).toBeNull();
  });
  it('unhxArray decodes exactly len canonical elements, in order, or returns null', () => {
    expect(unhxArray(['1', 'ff', '0'], 3)).toEqual([1n, 255n, 0n]);
    expect(unhxArray([], 0)).toEqual([]);
    expect(unhxArray(['1', '2'], 3)).toBeNull();
    expect(unhxArray(['1', '2', '3'], 2)).toBeNull();
    expect(unhxArray('12', 2)).toBeNull();
    expect(unhxArray({ length: 1, 0: '1' }, 1)).toBeNull();
    expect(unhxArray(['1', '01'], 2)).toBeNull();
    expect(unhxArray(['1', 2], 2)).toBeNull();
    expect(unhxArray([hx(PRIME)], 1)).toBeNull();
  });
});
