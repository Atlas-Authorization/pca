import { describe, expect, it } from 'vitest';
import { referenceComponentWat } from './index';

describe('referenceComponentWat', () => {
  it('the default component invokes handle 1 and imports nothing else', () => {
    const w = referenceComponentWat();
    expect(w.startsWith('(component\n  (import "pca:act/invoke@0.1.0" (instance $inv')).toBe(true);
    expect(w.endsWith('(export "run" (func $lifted)))\n')).toBe(true);
    expect(w).toContain('(call $invoke (i32.const 1) (i32.const 16))');
    expect(w).toContain('(if (result i32) (i32.load8_u (i32.const 16))');
    expect(w).toContain('(else (i32.load8_u (i32.load (i32.const 20)))))');
    expect(w).toContain('  \n  (core module $libc');
    expect(w).toContain('(canon lift (core func $run))');
    expect(w).not.toContain('get-arguments');
    expect(w).not.toContain('loop');
    expect(w.match(/^ {2}\(import /gm)).toHaveLength(1);
  });
  it('a handle number is used as given, including 0', () => {
    expect(referenceComponentWat({ handle: 5 })).toContain('(call $invoke (i32.const 5) (i32.const 16))');
    expect(referenceComponentWat({ handle: 0 })).toContain('(call $invoke (i32.const 0) (i32.const 16))');
  });
  it('spin loops forever instead of invoking', () => {
    const w = referenceComponentWat({ spin: true });
    expect(w).toContain('(loop $l (br $l)) (i32.const 0)');
    expect(w).not.toContain('(call $invoke (i32.const');
  });
  it('an extra import is emitted for the host to refuse', () => {
    const w = referenceComponentWat({ extraImport: 'wasi:cli/environment@0.2.0' });
    expect(w).toContain('(import "wasi:cli/environment@0.2.0" (instance (export "get-arguments" (func (result (list string))))))');
    expect(w.match(/^ {2}\(import /gm)).toHaveLength(2);
  });
});
