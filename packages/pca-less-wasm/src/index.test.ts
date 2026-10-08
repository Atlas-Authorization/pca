/**
 * Round-trip tests for the EXPERIMENTAL LESS code-based signature backend, exercised through the
 * WebAssembly binding (keypair -> sign -> open/verify, plus tamper rejection).
 *
 * The `.wasm` artifact is produced off-box by `~/.pca-vm-state/lessbuild.sh` (this Mac has no
 * wasi-sdk). When it is absent, the whole suite is SKIPPED rather than failed — this is a non-default
 * experimental package and CI must not break on a missing artifact. Once `wasm/less_cat1.wasm` is
 * dropped in, the suite runs for real.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { keygen, open, seedWith, sign, signDetached, sizes, verify, VARIANT } from './index';

const WASM = join(__dirname, '..', 'wasm', 'less_cat1.wasm');
const haveWasm = existsSync(WASM);
const d = haveWasm ? describe : describe.skip;

describe('pca-less-wasm metadata', () => {
  it('declares the compiled NIST Category 1 variant', () => {
    expect(VARIANT).toBe('less-252-45');
  });
});

d('LESS (code-based) signature core (wasm)', () => {
  it('exposes positive, sane byte sizes read from the wasm', () => {
    const s = sizes();
    expect(s.seed).toBeGreaterThan(0);
    expect(s.secretKey).toBeGreaterThan(0);
    expect(s.publicKey).toBeGreaterThan(s.secretKey);
    expect(s.signatureMax).toBeGreaterThan(0);
  });

  it('does a deterministic keypair -> sign -> open round-trip (attached)', () => {
    seedWith(new Uint8Array(32).map((_, i) => (i * 7 + 1) & 0xff));
    const { publicKey, secretKey } = keygen();
    const msg = new TextEncoder().encode('LESS wasm KAT: proof-carrying authority');
    const sm = sign(secretKey, msg);
    const r = open(publicKey, sm);
    expect(r.ok).toBe(true);
    expect(Buffer.from(r.message)).toEqual(Buffer.from(msg));
  });

  it('verifies a detached signature and rejects a tampered one', () => {
    seedWith(new Uint8Array(32).fill(9));
    const { publicKey, secretKey } = keygen();
    const msg = new TextEncoder().encode('detached payload');
    const sig = signDetached(secretKey, msg);
    expect(verify(publicKey, msg, sig)).toBe(true);

    const bad = sig.slice();
    bad[0] = (bad[0]! ^ 0x01) & 0xff;
    expect(verify(publicKey, msg, bad)).toBe(false);

    const wrongMsg = new TextEncoder().encode('detached payloaX');
    expect(verify(publicKey, wrongMsg, sig)).toBe(false);
  });
});
