/**
 * L0 backend — PUF (Physical Unclonable Function) UNCLONABLE attestation root.
 *
 * A fourth, independent attestation root for the multi-root N-of-M policy in `attestation.ts`, built to the
 * SAME `HardwareAttestationVerifier` seam as the SEV-SNP / Intel-TDX / NVIDIA-GPU-CC and PQ-software roots.
 * Its distinct property is UNCLONABILITY: the root identity is derived from a device's Physical Unclonable
 * Function — the uncontrollable manufacturing variation of a specific chip (SRAM power-up state, ring
 * oscillators, a TPM Endorsement Key, ...). The device cannot be copied, so the derived key cannot be
 * reproduced on any other device. This file is the SOFTWARE layer that turns a noisy PUF reading into a
 * stable cryptographic identity and verifies it: a fuzzy extractor, a provider abstraction, enrollment and
 * a verifier. The PUF hardware itself is the provider's.
 *
 * ── HONEST SCOPE — read this first. ─────────────────────────────────────────────────────────────────
 *   • PQ STATUS: PUF unclonability is a CLASSICAL property (manufacturing entropy — the root DEVICE cannot
 *     be copied). It is a DIFFERENT axis from quantum-resistance: it does not make the signature
 *     post-quantum. It COMPLEMENTS the PQ-software root (`attest-pq-software.ts`), it does not replace it.
 *     BUT the key the fuzzy extractor derives can itself carry a PQ SIGNATURE SUITE (ML-DSA), so a
 *     PUF-rooted identity can be BOTH unclonable AND post-quantum-signed, composing cleanly with the PQ
 *     root. Choose an `ml-dsa-*` suite at enrollment for that.
 *   • WHAT IS OURS vs THE PROVIDER'S: the fuzzy extractor (secure sketch + strong extractor), the enrollment
 *     registry and the verifier are ours and are FULLY BUILDABLE/TESTABLE in software (real crypto). The
 *     unclonable entropy source is the hardware's. On a device WITH a real PUF/TPM this is a genuine
 *     unclonable root; the `PufProvider` seam is where that hardware plugs in.
 *   • WEIGHTS: this root attests an UNCLONABLE DEVICE IDENTITY, not a silicon measurement of the loaded
 *     model weights. Its measured identity therefore carries `weights_measured: false` (software-measured);
 *     it can satisfy a plain `weights_allowlist` but never `require_measured_weights` on its own.
 *   • THE SIMULATED PUF IN TESTS IS CLONABLE. `createSimulatedPuf` is a DETERMINISTIC software stand-in so
 *     CI can exercise enrollment / reproduction / fuzzy-extraction without hardware. A simulated PUF is
 *     trivially clonable (its response is a pure function of a seed) and is NOT a real root of trust.
 *
 * ── THE FUZZY EXTRACTOR (real, vetted construction). ────────────────────────────────────────────────
 * A code-offset SECURE SKETCH over a linear REPETITION code plus an HKDF-SHA-256 STRONG EXTRACTOR
 * (Dodis–Ostrovsky–Reyzin–Smith). Enrollment reads a noisy response W, draws a random codeword C = Enc(m),
 * publishes helper data (the sketch `s = C ⊕ W`, a salt), and derives the key K = HKDF(W, salt).
 * Reproduction reads a noisy W', computes `C ⊕ e = W' ⊕ s` (e = W ⊕ W'), DECODES back to C (majority vote
 * per repetition block, correcting up to ⌊(rep−1)/2⌋ bit-flips PER BLOCK), recovers W = C ⊕ s and
 * re-derives the SAME K. Within the correction bound the key is bit-exact and stable; beyond it, decoding
 * yields a different W and therefore a different key (fail-closed). The sketch is standard secure-sketch
 * public helper data; it reveals no more than the code's redundancy.
 *
 * References: Dodis, Ostrovsky, Reyzin, Smith, "Fuzzy Extractors" (SIAM J. Comput. 2008); SRAM PUF key
 * generation; TPM 2.0 Endorsement Key as a device-unique root.
 */
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { b64u, canonicalBytes, hashCanonical, unb64u, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  type SigAlg,
  type SigSuite,
  type SuiteSignatureParts,
  encodeMlDsa87PublicKey,
  encodeMlDsaPublicKey,
  mlDsa65Keygen,
  mlDsa87Keygen,
  resolveSigAlg,
  signWithSuite,
  verifyWithSuite,
} from './pq';
import { attestationBinding, attestationBindingB64u } from './attestation';
import type {
  AttestationDocument,
  HardwareAttestationResult,
  HardwareAttestationVerifier,
  MeasuredIdentity,
} from './attestation';
import type { VerifyContext } from './pcactn';

/** Domain separator for the HKDF strong extractor (PUF response → key). */
export const PUF_EXTRACT_INFO = 'atlas-pca/puf-extract/v1';
/** Domain separator for the signed PUF attestation statement body. */
export const PUF_ATTEST_DOMAIN = 'atlas-pca/attest-puf/v1\0';
/** The derived key / strong-extractor output length (bytes) — seeds the PUF-derived signing key. */
export const PUF_KEY_BYTES = 32;

// ════════════════════════════════════════════════════════════════════════════════════════════════
// FUZZY EXTRACTOR — code-offset secure sketch (repetition code) + HKDF strong extractor.
// A PUF "response" is a bit vector represented as a Uint8Array of 0/1 bytes (one byte per bit) so Hamming
// distance is unambiguous. `n = rep * messageBits` is the response length.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** Parameters of the repetition-code fuzzy extractor. Response length n = `rep * messageBits`. */
export interface FuzzyExtractorParams {
  /** Repetition factor (ODD, >= 1). Corrects up to ⌊(rep−1)/2⌋ bit-flips per code block. */
  rep: number;
  /** Number of message bits (code blocks). */
  messageBits: number;
}

/** PUBLIC helper data produced at enrollment — reveals only the code's redundancy, never the key. */
export interface FuzzyExtractorHelper {
  /** b64u of the packed code-offset sketch bits (`C ⊕ W`). */
  sketch: string;
  /** b64u of the HKDF salt. */
  salt: string;
  /** Repetition factor. */
  rep: number;
  /** Message bits. */
  messageBits: number;
  /** Total response length in bits (`rep * messageBits`). */
  n: number;
}

/** The per-block Hamming correction bound of a repetition code. */
export function repetitionCorrectionBound(rep: number): number {
  return Math.floor((rep - 1) / 2);
}

function assertBits(b: Uint8Array, where: string): void {
  for (let i = 0; i < b.length; i++) if (b[i]! > 1) throw new RangeError(`${where}: response must be a 0/1 bit array`);
}

function xorBits(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i]! ^ b[i]!) & 1;
  return out;
}

function repEncode(message: Uint8Array, rep: number): Uint8Array {
  const out = new Uint8Array(message.length * rep);
  for (let i = 0; i < message.length; i++) {
    const bit = message[i]! & 1;
    for (let j = 0; j < rep; j++) out[i * rep + j] = bit;
  }
  return out;
}

function repDecode(code: Uint8Array, rep: number): Uint8Array {
  const k = code.length / rep;
  const out = new Uint8Array(k);
  for (let i = 0; i < k; i++) {
    let ones = 0;
    for (let j = 0; j < rep; j++) ones += code[i * rep + j]! & 1;
    out[i] = ones * 2 > rep ? 1 : 0; // strict majority; ties (even rep) resolve to 0 — use ODD rep
  }
  return out;
}

function packBits(bits: Uint8Array): Uint8Array {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) if (bits[i]! & 1) out[i >> 3]! |= 1 << (i & 7);
  return out;
}

function unpackBits(packed: Uint8Array, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (packed[i >> 3]! >> (i & 7)) & 1;
  return out;
}

function extractKey(responseBits: Uint8Array, salt: Uint8Array): Uint8Array {
  // Strong extractor: HKDF-SHA-256 over the packed stable response, domain-separated.
  return hkdf(nobleSha256, packBits(responseBits), salt, utf8(PUF_EXTRACT_INFO), PUF_KEY_BYTES);
}

/**
 * ENROLL a PUF response into a stable key + public helper data. `randomBytes` supplies the random codeword
 * message and the salt (injectable for deterministic tests). Throws on a malformed response or params.
 * NOTE: the key depends ONLY on the response W (not on the random codeword), so reproduction with the SAME
 * helper yields the SAME key for any noisy reading within the correction bound.
 */
export function fuzzyEnroll(
  responseBits: Uint8Array,
  params: FuzzyExtractorParams,
  randomBytes: (n: number) => Uint8Array,
): { key: Uint8Array; helper: FuzzyExtractorHelper } {
  if (!Number.isInteger(params.rep) || params.rep < 1 || params.rep % 2 === 0) throw new RangeError('fuzzyEnroll: rep must be an odd positive integer');
  if (!Number.isInteger(params.messageBits) || params.messageBits < 1) throw new RangeError('fuzzyEnroll: messageBits must be a positive integer');
  const n = params.rep * params.messageBits;
  if (responseBits.length !== n) throw new RangeError(`fuzzyEnroll: response length ${responseBits.length} != rep*messageBits ${n}`);
  assertBits(responseBits, 'fuzzyEnroll');
  const m = new Uint8Array(params.messageBits);
  const mr = randomBytes(params.messageBits);
  for (let i = 0; i < params.messageBits; i++) m[i] = mr[i]! & 1;
  const codeword = repEncode(m, params.rep);
  const sketch = xorBits(codeword, responseBits); // C ⊕ W
  const salt = randomBytes(32);
  const key = extractKey(responseBits, salt);
  return { key, helper: { sketch: b64u(packBits(sketch)), salt: b64u(salt), rep: params.rep, messageBits: params.messageBits, n } };
}

/**
 * REPRODUCE the key from a noisy response and the public helper data. Within the per-block correction bound
 * the returned key is bit-identical to enrollment; beyond it, a DIFFERENT key is returned (fail-closed — the
 * downstream signature then simply fails to verify). Throws only on structurally malformed helper/response.
 */
export function fuzzyReproduce(responseBits: Uint8Array, helper: FuzzyExtractorHelper): Uint8Array {
  if (!helper || !Number.isInteger(helper.rep) || !Number.isInteger(helper.messageBits) || helper.rep < 1 || helper.rep % 2 === 0) {
    throw new RangeError('fuzzyReproduce: malformed helper params');
  }
  const n = helper.rep * helper.messageBits;
  if (helper.n !== n) throw new RangeError('fuzzyReproduce: helper.n inconsistent with rep*messageBits');
  if (responseBits.length !== n) throw new RangeError(`fuzzyReproduce: response length ${responseBits.length} != ${n}`);
  assertBits(responseBits, 'fuzzyReproduce');
  const sketchBits = unpackBits(unb64u(helper.sketch), n);
  const corrupted = xorBits(responseBits, sketchBits); // W' ⊕ s = C ⊕ e
  const mHat = repDecode(corrupted, helper.rep);
  const cHat = repEncode(mHat, helper.rep);
  const wRec = xorBits(cHat, sketchBits); // C_hat ⊕ s = recovered W (== enrollment W within the bound)
  return extractKey(wRec, unb64u(helper.salt));
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// PUF PROVIDER abstraction.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * A source of PUF responses for a device. PRODUCTION BACKENDS (the real-root seam): an SRAM-PUF (read the
 * uninitialised SRAM power-up pattern), a TPM 2.0 Endorsement Key / EK certificate (device-unique), or a
 * vendor PUF IP block. Many devices already ship one of these. `response` returns a NOISY bit reading for a
 * challenge; successive reads differ by a bounded Hamming distance, which the fuzzy extractor corrects.
 */
export interface PufProvider {
  /** Stable device/provider id (used to look up the enrollment). */
  readonly id: string;
  /** Read the (noisy) PUF response bits for a challenge. Length must equal the enrolled `rep * messageBits`. */
  response(challenge: Uint8Array): Uint8Array;
}

/**
 * A DETERMINISTIC SIMULATED PUF — FOR TESTS ONLY. Its "golden" response is a pure function of (`seed`,
 * challenge), so it is TRIVIALLY CLONABLE and is NOT a real unclonable root. Use it to exercise enrollment,
 * reproduction and the fuzzy extractor in CI. An optional `flip` set injects deterministic bit-noise
 * (positions to toggle) so a test can dial the Hamming distance precisely; a different `seed` models a
 * DIFFERENT (cloned-attempt) device.
 */
export function createSimulatedPuf(opts: { id: string; seed: Uint8Array; length: number; flip?: Iterable<number> }): PufProvider {
  const flips = new Set<number>(opts.flip ?? []);
  const golden = (challenge: Uint8Array): Uint8Array => {
    const bits = new Uint8Array(opts.length);
    // Counter-mode SHA-256 PRG over (seed ‖ challenge ‖ ctr) → one bit per output bit position.
    const bytesNeeded = Math.ceil(opts.length / 8);
    const stream = new Uint8Array(Math.ceil(bytesNeeded / 32) * 32);
    for (let blk = 0; blk * 32 < stream.length; blk++) {
      const ctr = new Uint8Array(4);
      new DataView(ctr.buffer).setUint32(0, blk, false);
      const h = nobleSha256(concatBytes(opts.seed, challenge, ctr));
      stream.set(h, blk * 32);
    }
    for (let i = 0; i < opts.length; i++) bits[i] = (stream[i >> 3]! >> (i & 7)) & 1;
    return bits;
  };
  return {
    id: opts.id,
    response(challenge: Uint8Array): Uint8Array {
      const bits = golden(challenge);
      for (const pos of flips) if (pos >= 0 && pos < bits.length) bits[pos] = (bits[pos]! ^ 1) & 1;
      return bits;
    },
  };
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// REAL HARDWARE BACKEND — TPM 2.0 Endorsement Key as the unclonable entropy source.
//
// WHAT MAKES THIS UNCLONABLE. A TPM 2.0 Endorsement Key (EK) is derived on-chip from the TPM's Endorsement
// Primary Seed. The seed never leaves the chip and is NOT exportable, so the EK — and its public area — are
// unique to that specific TPM and cannot be reproduced on any other machine. Reading the EK public is
// deterministic (same chip → same bytes, every time), so there is effectively ZERO reading noise: the fuzzy
// extractor sees a stable response and reproduces the enrolled key bit-exactly, while a DIFFERENT TPM yields
// different EK bytes → a different derived response → a different fuzzy-extractor key that fails to verify
// under the enrolled public key. This is the SAME "the device cannot be copied" guarantee as an SRAM PUF; the
// entropy source is the vTPM / physical TPM (Azure Confidential / TrustedLaunch vTPM, a discrete/firmware TPM),
// NOT manufacturing-variation SRAM. It is a CLASSICAL unclonability property (see the honest-scope note at the
// top); choosing an `ml-dsa-*` suite at enrollment makes the PUF-rooted identity ALSO post-quantum-signed.
//
// Node has no native TPM API, so the backend shells out to `tpm2-tools` (TCG TSS) through an INJECTABLE
// command runner. The default runner spawns the tool SYNCHRONOUSLY via `node:child_process` (acquired lazily
// through `process.getBuiltinModule` so no static Node import is pulled into browser/portable bundles). Tests
// inject a deterministic mock runner; the default runner is used only on a real TPM host (and by the
// `scripts/tpm-ek-validate.mjs` validation script). FAIL-CLOSED everywhere: tpm2-tools absent, the TPM
// unavailable, a non-zero exit, or implausibly short EK material all THROW rather than fabricate a reading.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** HKDF domain separator binding the EK public area → the device-unique, stable PUF response. */
export const TPM_EK_PUF_DOMAIN = 'atlas-pca/puf-tpm-ek/v1';

/** Result of one `tpm2-tools` invocation, as seen by the provider (so a mock can model every outcome). */
export interface TpmCommandResult {
  /** Process exit status (0 = success). `null` when the process could not run / was signalled. */
  readonly status: number | null;
  /** Raw bytes written to stdout (e.g. the DER-encoded EK public area). */
  readonly stdout: Uint8Array;
  /** Captured stderr (diagnostics), if any. */
  readonly stderr?: string;
  /** Set when the tool could not be SPAWNED at all (e.g. tpm2-tools not installed: ENOENT). Fail-closed. */
  readonly error?: string;
}

/** An injectable `tpm2-tools` runner: runs `command` with `args` and returns its result. Must not throw for a
 * failed TPM/command — it returns a {@link TpmCommandResult} (with `error`/non-zero `status`) so the provider
 * fails closed deterministically. The default runner ({@link defaultTpmCommandRunner}) spawns synchronously. */
export type TpmCommandRunner = (command: string, args: readonly string[]) => TpmCommandResult;

/** Options for {@link TpmEkPufProvider}. */
export interface TpmEkPufProviderOptions {
  /** Stable device/provider id (used to look up the enrollment). */
  readonly id: string;
  /** Response length in BITS — MUST equal the enrolled `rep * messageBits`. */
  readonly length: number;
  /** Injectable command runner (default spawns `tpm2-tools` synchronously via `node:child_process`). */
  readonly run?: TpmCommandRunner;
  /** The `tpm2-tools` binary that reads the EK public area (default `tpm2_readpublic`). */
  readonly tool?: string;
  /** Persistent EK handle to read (default `0x81010001`, the TCG-standard RSA EK handle). Ignored if `args` set. */
  readonly ekHandle?: string;
  /** Full argv override for the read command. Default reads the EK public as DER to stdout from `ekHandle`. */
  readonly args?: readonly string[];
  /** Reject an EK public shorter than this many bytes (default 64) — guards against a truncated/empty read. */
  readonly minEkBytes?: number;
}

// --- Lazy, synchronous, bundler-safe access to node:child_process (Node >= 22.3 via getBuiltinModule). ----

interface NodeExecFileSyncOptions {
  readonly timeout?: number;
  readonly maxBuffer?: number;
  readonly stdio?: readonly ('ignore' | 'pipe' | 'inherit')[];
}
interface NodeChildProcessModule {
  execFileSync(file: string, args: readonly string[], options: NodeExecFileSyncOptions): Uint8Array;
}

function loadNodeChildProcess(): NodeChildProcessModule {
  const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
  if (!proc || typeof proc.getBuiltinModule !== 'function') {
    throw new Error('TpmEkPufProvider: no Node runtime (process.getBuiltinModule, Node >= 22.3) to spawn tpm2-tools; inject opts.run (fail closed)');
  }
  const mod = proc.getBuiltinModule('node:child_process');
  if (!mod || typeof (mod as { execFileSync?: unknown }).execFileSync !== 'function') {
    throw new Error('TpmEkPufProvider: node:child_process.execFileSync unavailable (fail closed)');
  }
  return mod as NodeChildProcessModule;
}

function toU8(b: Uint8Array): Uint8Array {
  return Uint8Array.from(b);
}

/**
 * Default command runner: spawns `tpm2-tools` SYNCHRONOUSLY (the {@link PufProvider.response} contract is
 * synchronous). Never throws for a tool/TPM failure — it normalises a non-zero exit or a spawn failure
 * (ENOENT when tpm2-tools is not installed, EACCES, …) into a {@link TpmCommandResult} so the provider fails
 * closed. Only a missing Node runtime throws (there is nothing to spawn with).
 */
export function defaultTpmCommandRunner(command: string, args: readonly string[]): TpmCommandResult {
  const cp = loadNodeChildProcess();
  try {
    const stdout = cp.execFileSync(command, args, { timeout: 15_000, maxBuffer: 1 << 20, stdio: ['ignore', 'pipe', 'pipe'] });
    return { status: 0, stdout: toU8(stdout) };
  } catch (e) {
    const err = e as { status?: unknown; stdout?: unknown; stderr?: unknown; code?: unknown; message?: unknown };
    const stderr = err.stderr instanceof Uint8Array ? new TextDecoder().decode(err.stderr) : typeof err.message === 'string' ? err.message : undefined;
    const stdout = err.stdout instanceof Uint8Array ? toU8(err.stdout) : new Uint8Array(0);
    // A spawn failure (tpm2-tools absent / not executable) has a string `code` and no numeric `status`.
    if (typeof err.status !== 'number') {
      const code = typeof err.code === 'string' ? err.code : 'spawn failed';
      return { status: null, stdout, stderr, error: `${command}: ${code}` };
    }
    return { status: err.status, stdout, stderr };
  }
}

/**
 * A {@link PufProvider} backed by a real TPM 2.0 Endorsement Key. Each {@link response} reads the device's
 * EK public area via `tpm2-tools` and derives a STABLE, device-unique bit response that feeds the existing
 * fuzzy extractor (so enrollment and reproduction use the same code path as any other PUF). Because the EK is
 * non-exportable and device-unique, the derived response — and therefore the enrolled key — cannot be
 * reproduced on another machine (the unclonable property). FAIL-CLOSED: any tooling/TPM failure throws.
 */
export class TpmEkPufProvider implements PufProvider {
  readonly id: string;
  private readonly length: number;
  private readonly run: TpmCommandRunner;
  private readonly tool: string;
  private readonly args: readonly string[];
  private readonly minEkBytes: number;

  constructor(opts: TpmEkPufProviderOptions) {
    if (!opts || typeof opts.id !== 'string' || opts.id.length === 0) throw new TypeError('TpmEkPufProvider: id must be a non-empty string');
    if (!Number.isInteger(opts.length) || opts.length < 1) throw new RangeError('TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)');
    if (opts.minEkBytes !== undefined && (!Number.isInteger(opts.minEkBytes) || opts.minEkBytes < 1)) throw new RangeError('TpmEkPufProvider: minEkBytes must be a positive integer');
    this.id = opts.id;
    this.length = opts.length;
    this.run = opts.run ?? defaultTpmCommandRunner;
    this.tool = typeof opts.tool === 'string' && opts.tool.length > 0 ? opts.tool : 'tpm2_readpublic';
    const ekHandle = typeof opts.ekHandle === 'string' && opts.ekHandle.length > 0 ? opts.ekHandle : '0x81010001';
    // Read the persistent EK public area as DER to stdout; `-Q` suppresses the informational YAML so stdout
    // carries only the serialized public key. Override via `opts.args` for a context-file / alternate flow.
    this.args = opts.args ?? ['-c', ekHandle, '-f', 'der', '-o', '/dev/stdout', '-Q'];
    this.minEkBytes = opts.minEkBytes ?? 64;
  }

  /**
   * Read the device-unique, STABLE TPM Endorsement-Key public area (fail-closed). Public so a validation
   * script can hash it for a fixture. Returns only PUBLIC material (the EK public area); no private key.
   */
  readEkPublic(): Uint8Array {
    let res: TpmCommandResult;
    try {
      res = this.run(this.tool, this.args);
    } catch (e) {
      throw new Error(`TpmEkPufProvider: tpm2-tools invocation threw (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
    }
    if (!res || typeof res !== 'object') throw new Error('TpmEkPufProvider: command runner returned no result (fail closed)');
    if (typeof res.error === 'string' && res.error.length > 0) throw new Error(`TpmEkPufProvider: tpm2-tools unavailable (fail closed): ${res.error}`);
    if (res.status !== 0) throw new Error(`TpmEkPufProvider: '${this.tool}' exited with status ${String(res.status)} (fail closed)${res.stderr ? `: ${res.stderr.trim()}` : ''}`);
    const ek = res.stdout;
    if (!(ek instanceof Uint8Array) || ek.length < this.minEkBytes) {
      throw new Error(`TpmEkPufProvider: EK public too short (${ek instanceof Uint8Array ? ek.length : 0} < ${this.minEkBytes} bytes) — TPM unavailable or wrong handle (fail closed)`);
    }
    return ek;
  }

  /**
   * Read the EK public area and derive the STABLE, device-unique PUF response for `challenge`. The EK read is
   * deterministic, so successive reads are bit-identical (zero noise); the fuzzy extractor therefore
   * reproduces the enrolled key exactly. A different TPM returns a different EK → a different response here.
   */
  response(challenge: Uint8Array): Uint8Array {
    const ek = this.readEkPublic();
    // Device-unique stable secret: HKDF over the EK public area, challenge-bound (salt = domain, info = challenge).
    const secret = hkdf(nobleSha256, ek, utf8(TPM_EK_PUF_DOMAIN), challenge, 32);
    return expandSecretToBits(secret, this.length);
  }
}

/** Expand a 32-byte secret into `length` 0/1 bits via a counter-mode SHA-256 PRG (mirrors the simulated PUF). */
function expandSecretToBits(secret: Uint8Array, length: number): Uint8Array {
  const bits = new Uint8Array(length);
  const bytesNeeded = Math.ceil(length / 8);
  const nblocks = Math.max(1, Math.ceil(bytesNeeded / 32));
  const stream = new Uint8Array(nblocks * 32);
  for (let blk = 0; blk < nblocks; blk++) {
    const ctr = new Uint8Array(4);
    new DataView(ctr.buffer).setUint32(0, blk, false);
    stream.set(nobleSha256(concatBytes(secret, ctr)), blk * 32);
  }
  for (let i = 0; i < length; i++) bits[i] = (stream[i >> 3]! >> (i & 7)) & 1;
  return bits;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// PUF-derived signing key — may be CLASSICAL (ed25519) or POST-QUANTUM (ml-dsa-65 / ml-dsa-87).
// The fuzzy-extractor output seeds the keypair deterministically, so the SAME PUF reproduces the SAME key.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** The PUF-derived suites this root supports (each seeds deterministically from the 32-byte extractor output). */
export type PufSuite = 'ed25519' | 'ml-dsa-65' | 'ml-dsa-87';

function assertPufSuite(alg: SigAlg): PufSuite {
  if (alg === 'ed25519' || alg === 'ml-dsa-65' || alg === 'ml-dsa-87') return alg;
  throw new RangeError(`PUF root: unsupported derived suite '${alg}' (use ed25519, ml-dsa-65 or ml-dsa-87)`);
}

/** A signer built from a reproduced PUF key: its public key (b64u) and a suite-correct signer over a message. */
interface PufDerivedSigner {
  publicKey: string;
  sign(msg: Uint8Array): SuiteSignatureParts;
}

function pufSignerFromSeed(alg: PufSuite, seed: Uint8Array): PufDerivedSigner {
  switch (alg) {
    case 'ed25519':
      return { publicKey: b64u(publicKeyOf(seed)), sign: (msg) => signWithSuite('ed25519', { edSecret: seed }, msg) };
    case 'ml-dsa-65': {
      const kp = mlDsa65Keygen(seed);
      return { publicKey: encodeMlDsaPublicKey(kp.publicKey), sign: (msg) => signWithSuite('ml-dsa-65', { mlDsa: kp }, msg) };
    }
    case 'ml-dsa-87': {
      const kp = mlDsa87Keygen(seed);
      return { publicKey: encodeMlDsa87PublicKey(kp.publicKey), sign: (msg) => signWithSuite('ml-dsa-87', { mlDsa87: kp }, msg) };
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Enrollment + attestation statement + verifier.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** The enrolled PUBLIC identity of a PUF device. Contains no secret — the key never leaves the device. */
export interface PufEnrollment {
  /** The provider/device id this enrollment is for. */
  providerId: string;
  /** b64u challenge the PUF was enrolled under (re-used at attestation). */
  challenge: string;
  /** The PUF-derived key suite (ed25519 / ml-dsa-65 / ml-dsa-87). */
  alg: PufSuite;
  /** b64u PUF-derived public key — the unclonable identity. */
  publicKey: string;
  /** PUBLIC fuzzy-extractor helper data. */
  helper: FuzzyExtractorHelper;
  /** `hashCanonical(helper)` — binds the helper so a swapped helper is detected (fail-closed). */
  helperCommitment: string;
}

/** A signed PUF attestation statement. Signed by the PUF-DERIVED key; the verifier checks it under the enrolled public key. */
export interface PufAttestationStatement {
  /** The provider/device id (selects the enrolled identity). */
  provider_id: string;
  /** The measured runtime/workload digest (software-measured; the PUF roots the IDENTITY, not this). */
  measurement: string;
  /** Optional measured loaded-weights digest (software-measured — not silicon-rooted). */
  weights_digest?: string;
  /** b64u `attestationBinding({holderPub, grantRef, epoch, nonce})`. */
  binding: string;
  /** The PUF-derived key's suite (must equal the enrolled suite). */
  alg: PufSuite;
  /** b64u primary signature under the PUF-derived key. */
  sig: string;
  /** b64u PQ signature — reserved for hybrid PUF suites (unused by the supported pure suites). */
  pq_sig?: string;
}

type PufStatementBody = Omit<PufAttestationStatement, 'sig' | 'pq_sig'>;

function statementMessage(body: PufStatementBody): Uint8Array {
  const d = canonicalBytes(body);
  const p = utf8(PUF_ATTEST_DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

/** Options for {@link enrollPuf}. */
export interface EnrollPufOptions extends FuzzyExtractorParams {
  /** The PUF-derived key suite (default `ml-dsa-65` — unclonable AND post-quantum). */
  alg?: PufSuite;
  /** Randomness for the fuzzy extractor (codeword + salt). Injectable for deterministic tests. */
  randomBytes?: (n: number) => Uint8Array;
}

/**
 * ENROLL a PUF device: read its response under `challenge`, run the fuzzy extractor to get a stable key +
 * public helper data, derive the signing keypair, and return the PUBLIC enrolled identity. The secret key
 * never leaves this function (it is re-derived on-device at attestation). Throws on malformed inputs.
 */
export function enrollPuf(provider: PufProvider, challenge: Uint8Array, opts: EnrollPufOptions): PufEnrollment {
  const alg = assertPufSuite(opts.alg ?? 'ml-dsa-65');
  const randomBytes = opts.randomBytes ?? defaultRandomBytes;
  const responseBits = provider.response(challenge);
  const { key, helper } = fuzzyEnroll(responseBits, { rep: opts.rep, messageBits: opts.messageBits }, randomBytes);
  const signer = pufSignerFromSeed(alg, key);
  const enrollment: PufEnrollment = {
    providerId: provider.id,
    challenge: b64u(challenge),
    alg,
    publicKey: signer.publicKey,
    helper,
    helperCommitment: '',
  };
  enrollment.helperCommitment = hashCanonical(helper);
  return enrollment;
}

/** A device-side attestor that reproduces the PUF key and signs statements. */
export interface PufAttestor {
  attest(claims: { measurement: string; weights_digest?: string; holder_pub: string; grant_ref: string; epoch: number; nonce: string }): PufAttestationStatement;
}

/**
 * Build a device-side PUF attestor. Each `attest` REPRODUCES the key from a fresh (noisy) PUF reading via
 * the fuzzy extractor, so only the device holding the real PUF can produce a statement that verifies under
 * the enrolled public key. (With the simulated PUF this is deterministic — see the honest-scope note.)
 */
export function createPufAttestor(provider: PufProvider, enrollment: PufEnrollment): PufAttestor {
  const alg = assertPufSuite(enrollment.alg);
  const challenge = unb64u(enrollment.challenge);
  return {
    attest(claims): PufAttestationStatement {
      const responseBits = provider.response(challenge);
      const key = fuzzyReproduce(responseBits, enrollment.helper);
      const signer = pufSignerFromSeed(alg, key);
      const binding = attestationBindingB64u({ holderPub: claims.holder_pub, grantRef: claims.grant_ref, epoch: claims.epoch, nonce: claims.nonce });
      const body: PufStatementBody = {
        provider_id: provider.id,
        measurement: claims.measurement,
        binding,
        alg,
        ...(claims.weights_digest !== undefined ? { weights_digest: claims.weights_digest } : {}),
      };
      const parts = signer.sign(statementMessage(body));
      return { ...body, sig: parts.sig, ...(parts.pq_sig !== undefined ? { pq_sig: parts.pq_sig } : {}) };
    },
  };
}

/** A registry of enrolled PUF identities, keyed by provider id. */
export interface PufEnrollmentRegistry {
  register(enrollment: PufEnrollment): void;
  lookup(providerId: string): PufEnrollment | undefined;
}

/** An in-memory PUF enrollment registry (later duplicates for an id overwrite earlier ones). */
export function createPufEnrollmentRegistry(enrollments: PufEnrollment[] = []): PufEnrollmentRegistry {
  const byId = new Map<string, PufEnrollment>();
  for (const e of Array.isArray(enrollments) ? enrollments : []) if (e && typeof e.providerId === 'string') byId.set(e.providerId, e);
  return {
    register(e) {
      if (e && typeof e.providerId === 'string') byId.set(e.providerId, e);
    },
    lookup(id) {
      return byId.get(id);
    },
  };
}

/** Acceptance policy for a verified PUF statement. `measurements` is REQUIRED and NON-EMPTY (no accept-all). */
export interface PufPolicy {
  /** Allowed measurement values. REQUIRED and NON-EMPTY. */
  measurements: string[];
  /** Allowed measured-weights digests. Omitted/empty => not gated here. */
  weightsMeasurements?: string[];
  /** Map a verified statement into the `MeasuredIdentity` agent_binding is checked against. */
  deriveIdentity?: (statement: PufAttestationStatement, enrollment: PufEnrollment) => MeasuredIdentity;
}

export interface PufVerifierOptions {
  /** Resolve the enrolled identity for a statement's provider id (e.g. from a {@link PufEnrollmentRegistry}). */
  resolveEnrollment: (providerId: string, document: AttestationDocument, ctx: VerifyContext) => PufEnrollment | undefined | Promise<PufEnrollment | undefined>;
  /** Acceptance policy (measurement allowlist required). */
  policy: PufPolicy;
  /** Require the PUF-derived key to carry a PQ suite (default false). When set, an ed25519 PUF key is denied. */
  requirePq?: boolean;
  /** EVIDENCE SEAM: produce the signed PUF statement for an action. If omitted, the verifier fails closed. */
  resolveEvidence?: (
    document: AttestationDocument,
    ctx: VerifyContext,
  ) => PufAttestationStatement | undefined | Promise<PufAttestationStatement | undefined>;
}

/**
 * Build a `HardwareAttestationVerifier` backed by the PUF unclonable root. Given an attestation document +
 * context it resolves the signed statement (evidence seam) and the enrolled identity, then:
 *   1. checks the enrollment's helper commitment (a swapped helper is rejected);
 *   2. requires the statement suite to equal the enrolled suite (and, if `requirePq`, a PQ suite);
 *   3. verifies the signature under the ENROLLED public key (never a key from the statement) — only the
 *      device that can reproduce the PUF key signs acceptably, so a cloned/other device is rejected;
 *   4. confirms `binding === attestationBinding(expected)`;
 *   5. applies the acceptance policy and returns the measured identity (`weights_measured: false`).
 * Fails CLOSED with a specific reason on any mismatch or error.
 */
export function createPufVerifier(opts: PufVerifierOptions): HardwareAttestationVerifier {
  if (!opts?.policy || !Array.isArray(opts.policy.measurements) || opts.policy.measurements.length === 0) {
    throw new TypeError('createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
  }
  if (typeof opts.resolveEnrollment !== 'function') throw new TypeError('createPufVerifier: resolveEnrollment is required');
  const policy = opts.policy;
  const requirePq = opts.requirePq === true;
  const deriveIdentity = policy.deriveIdentity ?? defaultPufIdentity;

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no PUF evidence resolver configured (fail closed)');
        const st = await opts.resolveEvidence(input.document, input.ctx);
        if (!st || typeof st !== 'object' || typeof st.provider_id !== 'string' || typeof st.alg !== 'string') return fail('no PUF attestation statement for this action');

        const enr = await opts.resolveEnrollment(st.provider_id, input.document, input.ctx);
        if (!enr) return fail(`no PUF enrollment registered for provider '${st.provider_id}'`);

        // (1) helper integrity
        if (typeof enr.helperCommitment !== 'string' || enr.helperCommitment !== hashCanonical(enr.helper)) {
          return fail('PUF enrollment helper commitment mismatch (helper tampered)');
        }

        // (2) suite agreement
        if (st.alg !== enr.alg) return fail(`PUF statement suite '${st.alg}' does not match the enrolled suite '${enr.alg}'`);
        const suite: SigSuite | null = resolveSigAlg(st.alg);
        if (suite === null) return fail(`PUF statement declares an unknown signature alg '${String(st.alg)}'`);
        const suiteHasPq = suite.hasMlDsa || suite.hasSlhDsa || suite.hasMlDsa87 || suite.hasSlhDsa256s;
        if (requirePq && !suiteHasPq) return fail(`PQ required: PUF-derived suite '${suite.alg}' is classical`);

        // (3) signature under the ENROLLED public key (a cloned/other PUF derives a different key → fails here)
        const { sig, pq_sig, ...body } = st;
        const message = statementMessage(body);
        const ok = verifyWithSuite(
          suite.alg,
          { edPub: enr.publicKey, mlDsaPub: enr.publicKey, slhDsaPub: enr.publicKey, mlDsa87Pub: enr.publicKey, slhDsa256sPub: enr.publicKey },
          message,
          { sig, pq_sig },
        );
        if (!ok) return fail('PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)');

        // (4) binding
        if (!input.expected) return fail('no expected attestation binding supplied');
        let expectedB64u: string;
        try {
          expectedB64u = b64u(attestationBinding(input.expected));
        } catch (e) {
          return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
        }
        if (typeof st.binding !== 'string' || st.binding !== expectedB64u) return fail('PUF statement binding mismatch (holder/grant/epoch/nonce)');

        // (5) policy
        if (Array.isArray(policy.measurements) && policy.measurements.length > 0 && !policy.measurements.includes(st.measurement)) {
          return fail('measurement not in policy allowlist');
        }
        if (Array.isArray(policy.weightsMeasurements) && policy.weightsMeasurements.length > 0) {
          if (typeof st.weights_digest !== 'string' || !policy.weightsMeasurements.includes(st.weights_digest)) {
            return fail('measured weights digest not in policy allowlist');
          }
        }

        const measured = deriveIdentity(st, enr);
        return { ok: true, bound: true, measured, hostAsserted: { provider_id: st.provider_id, suite: suite.alg } };
      } catch (e) {
        return fail(`puf verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}

/**
 * Default identity for a verified PUF statement. HONEST: `weights_measured` is false — the PUF roots an
 * UNCLONABLE DEVICE IDENTITY, not a silicon measurement of the loaded weights.
 */
function defaultPufIdentity(st: PufAttestationStatement, _enr: PufEnrollment): MeasuredIdentity {
  return {
    model_id: '',
    weights_digest: typeof st.weights_digest === 'string' ? st.weights_digest : '',
    weights_measured: false,
    runtime_measurement: st.measurement,
    operator: '',
  };
}

/** Default CSPRNG for enrollment randomness (codeword + salt). Lazily uses WebCrypto; never in the verify hot path. */
function defaultRandomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  const g: { getRandomValues?: (a: Uint8Array) => Uint8Array } | undefined = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (g && typeof g.getRandomValues === 'function') {
    g.getRandomValues(out);
    return out;
  }
  throw new Error('enrollPuf: no secure RNG available; pass opts.randomBytes');
}
