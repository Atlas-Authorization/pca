/**
 * The reference tool as a component in the WebAssembly text format: no toolchain is needed to see the canonical ABI work. It
 * imports only `pca:act/invoke@0.1.0` and exports `run: func() -> s32`, which calls `invoke(handle)` and returns the first byte of the
 * result (or the negative host code). Lowering `invoke` needs linear memory and a realloc, so a tiny bump allocator module
 * provides them (the standard shim pattern).
 */
export interface ReferenceComponentOptions {
  /** The handle `run` invokes. Default 1. */
  handle?: number;
  /** Make `run` loop forever instead (to show the fuel limit). */
  spin?: boolean;
  /** An extra import the host must refuse (ambient authority). */
  extraImport?: string;
}

export function referenceComponentWat(o: ReferenceComponentOptions = {}): string {
  const extra = o.extraImport ? `(import "${o.extraImport}" (instance (export "get-arguments" (func (result (list string))))))` : '';
  const body = o.spin
    ? `(loop $l (br $l)) (i32.const 0)`
    : `(call $invoke (i32.const ${o.handle ?? 1}) (i32.const 16))
       (if (result i32) (i32.load8_u (i32.const 16))
         (then (i32.load (i32.const 20)))
         (else (i32.load8_u (i32.load (i32.const 20)))))`;
  return `(component
  (import "pca:act/invoke@0.1.0" (instance $inv
    (export "handle-count" (func (result u32)))
    (export "invoke" (func (param "handle" u32) (result (result (list u8) (error s32)))))))
  ${extra}
  (core module $libc
    (memory (export "memory") 1 1)
    (global $bump (mut i32) (i32.const 1024))
    (func (export "realloc") (param $old i32) (param $oldsz i32) (param $align i32) (param $new i32) (result i32)
      (local $p i32)
      (local.set $p (global.get $bump))
      (global.set $bump (i32.add (local.get $p) (local.get $new)))
      (local.get $p)))
  (core instance $libc (instantiate $libc))
  (alias core export $libc "memory" (core memory $mem))
  (alias core export $libc "realloc" (core func $realloc))
  (core func $count (canon lower (func $inv "handle-count")))
  (core func $invoke (canon lower (func $inv "invoke") (memory $mem) (realloc $realloc)))
  (core module $main
    (import "libc" "memory" (memory 1))
    (import "host" "count" (func $count (result i32)))
    (import "host" "invoke" (func $invoke (param i32 i32)))
    (func (export "run") (result i32)
      ${body}))
  (core instance $host (export "count" (func $count)) (export "invoke" (func $invoke)))
  (core instance $main (instantiate $main (with "libc" (instance $libc)) (with "host" (instance $host))))
  (alias core export $main "run" (core func $run))
  (func $lifted (result s32) (canon lift (core func $run)))
  (export "run" (func $lifted)))
`;
}
