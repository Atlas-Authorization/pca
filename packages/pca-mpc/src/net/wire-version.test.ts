/**
 * R5-G1: the OT tweak change (R4-12) is a wire change, so old and new peers must fail with a typed `version` abort at
 * the hello frame, never pass hello and then silently diverge inside the OT layer.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as tls from 'node:tls';
import { describe, expect, it } from 'vitest';
import { generateIdentity, readPem } from './certs';
import { Mesh } from './mesh';
import { T, waitListening, reservePorts } from './test-timing';
import { ABORT_KINDS, NetAbort, WIRE_VERSION, encodeFrame, peekVersion, versionMismatch } from './wire';
import { otTweakDomain } from '../otx';
import { createHash } from 'node:crypto';

async function oldPeerHello(v: number, raw?: Record<string, unknown>): Promise<{ e: unknown; clean: () => void }> {
  const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-ver-'));
  const a = generateIdentity(join(dir, 'a'), 'a');
  const b = generateIdentity(join(dir, 'b'), 'b');
  const [pa, pb] = (await reservePorts(2)) as [number, number];
  const nodes = [
    { id: 0, host: '127.0.0.1', port: pa, certPem: readPem(a.certPath) },
    { id: 1, host: '127.0.0.1', port: pb, certPem: readPem(b.certPath) },
  ];
  const mesh = new Mesh({
    selfId: 0, nodes, linkTo: [1], keyPem: readPem(a.keyPath), certPem: readPem(a.certPath),
    sessionId: 's', listenHost: '127.0.0.1', connectTimeoutMs: T(30_000), recvTimeoutMs: T(10_000),
  });
  const connected = mesh.connect().catch((x) => x);
  await waitListening(pa);
  const sock = tls.connect({ host: '127.0.0.1', port: pa, key: readPem(b.keyPath), cert: readPem(b.certPath), ca: [nodes[0]!.certPem], checkServerIdentity: () => undefined });
  sock.on('error', () => undefined);
  await new Promise<void>((r) => sock.once('secureConnect', () => r()));
  sock.write(encodeFrame((raw ?? { v, ty: 'hello', sid: 's', seq: 0, rd: 'hello', d: { id: 1 } }) as never));
  const e = await connected;
  return { e, clean: () => { sock.destroy(); mesh.fail(mesh.failed ?? new NetAbort('local', null, 0, 'done')); rmSync(dir, { recursive: true, force: true }); } };
}

describe('R5-G1 wire version', () => {
  it('is bumped past the pre-R4-12 version 1', () => {
    expect(WIRE_VERSION).toBe(2);
    expect(ABORT_KINDS.has('version')).toBe(true);
  });
  it('a pre-R4-12 peer (v=1) is refused at hello with a typed version abort', async () => {
    const { e, clean } = await oldPeerHello(1);
    expect(e).toBeInstanceOf(NetAbort);
    expect((e as NetAbort).kind).toBe('version');
    expect((e as NetAbort).message).toMatch(/wire version 1/);
    clean();
  }, T(20_000));
  it('a future peer (v=3) is refused the same way; garbage stays malformed', async () => {
    const f = await oldPeerHello(3);
    expect((f.e as NetAbort).kind).toBe('version');
    f.clean();
    expect(peekVersion(Buffer.from('{"v":1.5}'))).toBeNull();
    expect(peekVersion(Buffer.from('nope'))).toBeNull();
    expect(peekVersion(Buffer.from('{"v":7}'))).toBe(7);
  }, T(20_000));
  it('R6-CORE-06: garbage that merely carries an integer v != 2 is malformed, not version', async () => {
    const g = await oldPeerHello(3, { v: 3, x: 'junk' });
    expect(g.e).toBeInstanceOf(NetAbort);
    expect((g.e as NetAbort).kind).toBe('malformed');
    g.clean();
    const h = (o: unknown) => Buffer.from(JSON.stringify(o));
    const ok = { ty: 'hello', sid: 's', seq: 0, rd: 'hello', d: { id: 1 } };
    expect(versionMismatch(h({ v: 1, ...ok }))).toBe(1);
    expect(versionMismatch(h({ v: 3, ...ok, ty: 'msg' }))).toBe(3);
    expect(versionMismatch(h({ v: 2, ...ok }))).toBeNull(); // our own version is never a mismatch
    expect(versionMismatch(h({ v: 3, x: 'junk' }))).toBeNull();
    expect(versionMismatch(h({ v: 1 }))).toBeNull();
    expect(versionMismatch(h({ v: 3, ...ok, ty: 'bogus' }))).toBeNull();
    expect(versionMismatch(h({ v: 3, ...ok, seq: -1 }))).toBeNull();
    expect(versionMismatch(h({ v: 3, ...ok, extra: 1 }))).toBeNull();
    expect(versionMismatch(h({ v: 1.5, ...ok }))).toBeNull();
    expect(versionMismatch(Buffer.from('nope'))).toBeNull();
  }, T(20_000));
  it('the OT tweak domain is versioned: it differs from the legacy (unversioned) label derivation', () => {
    const binding = new Uint8Array(32).fill(7);
    const d = createHash('sha256').update(new TextEncoder().encode('atlas-pca-mpc/ot-crh-tweak-domain')).update(binding).digest();
    const legacy = [d.readUInt32LE(0), d.readUInt32LE(4)];
    const now = Array.from(otTweakDomain(binding));
    expect(now).not.toEqual(legacy);
  });
});
