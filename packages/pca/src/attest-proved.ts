/* eslint-disable @typescript-eslint/no-explicit-any */
// attest-proved.ts - the PRODUCTION implementations of verifyAttestation, createAttestationVerifier, verifyAllowlistDurable and
// verifyAllowlistAnchored. Every DECISION (the stage order and first failure, the validity window and nonce age on integer
// operands, the hook's single-use consume rule, the durable high-water-mark update and outcome, the anchored head freshness,
// cache stage and feed scan) is made by the Dafny-proved code of formal/dafny/Attest.dfy (via @atlasauth/pca-verified-core
// `attestBridge`). This file is TRUSTED GLUE: it evaluates the primitives (signature checks, canonical bytes, envelope reads,
// tree-head signatures, nonce entropy, the hardware verifier) and hands booleans / integers to the proved functions, and
// renders the proved verdict into the unchanged legacy reason strings. Operands that are not integers (a fractional skew or
// clock) use the same double arithmetic as before. The public functions in attestation.ts / attest-allowlist*.ts forward here.
// Differentially tested against frozen copies of the hand-written code (packages/pca-verified-core/test/ext-attest.diff.test.ts).
// See docs/pca/security/verified-core.md; scripts/check-verified-core.sh fails if the forwarding calls are removed.
import {
  attestationBindingB64u,
  nonceEntropyOk,
  MAX_ATTESTATION_AGE_MS,
  type AttestationDocument,
  type AttestationHookResult,
  type AttestationVerdict,
  type AttestationVerifierOpts,
  type ExpectedAttestationBinding,
  type HardwareAttestationResult,
  type HardwareAttestationVerifier,
  type MeasuredIdentity,
} from './attestation';
import { canonicalBytes, utf8 } from './hash';
import { snapshotConfig } from './config-snapshot';
import { readEnvelope } from './envelope';
import { resolveSigAlg, verifyPinnedSuite } from './pq';
import { verifyAllowlistManifest, type VerifyAllowlistOptions, type VerifyAllowlistResult } from './attest-allowlist';
import type { DurableKv } from './durable-state';
import {
  allowlistAnchorCommit,
  type AllowlistAnchorEvidence,
  type AllowlistAnchorEntry,
  type AnchoredResult,
  type VerifyAnchoredOptions,
} from './attest-allowlist-anchor';
import { ledgerRootOf, verifyHeadConsistency, verifyLedgerInclusion, verifyTreeHead } from './ledger';
import { attestBridge, matchAgentBindingVerified } from '@atlasauth/pca-verified-core';

const { A, DF, bn, seqOf, kindName, none, Interner } = attestBridge;

const DOMAIN = 'atlas-pca/attest/v1\0';
function attestMessage(body: unknown): Uint8Array {
  const d = canonicalBytes(body);
  const p = utf8(DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

const isInt = Number.isSafeInteger;
/** nonce age: proved NonceAge when every operand is an integer (skew floored, which is exact), the same double arithmetic otherwise. */
function nonceAgeReason(issued: unknown, nowMs: number, skew: number, maxAge: number): string | null {
  if (typeof issued !== 'number' || !Number.isFinite(issued)) return 'server nonce issue time unknown (cannot establish freshness)';
  const upper = maxAge + skew;
  if (isInt(issued) && isInt(nowMs) && Number.isFinite(skew) && Number.isFinite(upper) && Math.abs(upper) < 2 ** 52) {
    const fs = Math.floor(skew);
    const r = DF.NonceAge(true, bn(issued), bn(nowMs), bn(fs), bn(Math.floor(upper) - fs));
    if (r.is_AgeFuture) return 'nonce issued in the future';
    if (r.is_AgeStale) return 'attestation nonce expired (stale quote)';
    return null;
  }
  if (nowMs + skew < issued) return 'nonce issued in the future';
  if (nowMs - issued > maxAge + skew) return 'attestation nonce expired (stale quote)';
  return null;
}

type WinRes = 'malformed' | 'notyet' | 'expired' | 'valid';
function windowDecision(nowMs: number, skew: number, iat: number, exp: number): WinRes {
  if (!Number.isFinite(iat) || !Number.isFinite(exp)) return 'malformed';
  if (isInt(iat) && isInt(exp) && isInt(nowMs) && Number.isFinite(skew)) {
    const r = DF.Window(bn(nowMs), bn(Math.floor(skew)), bn(iat), bn(exp));
    return r.is_WinMalformed ? 'malformed' : r.is_WinNotYet ? 'notyet' : r.is_WinExpired ? 'expired' : 'valid';
  }
  if (exp < iat) return 'malformed';
  if (nowMs + skew < iat) return 'notyet';
  if (nowMs - skew > exp) return 'expired';
  return 'valid';
}

export async function verifyAttestationProved(input: {
  document: AttestationDocument | undefined;
  ctx: any;
  expected: ExpectedAttestationBinding;
  nowMs: number;
  trustedAttestorKeys: Iterable<string>;
  pqPins?: any;
  allowUnboundPq?: boolean;
  hardwareVerifier?: HardwareAttestationVerifier;
  maxNonceAgeMs?: number;
  clockSkewMs?: number;
}): Promise<AttestationVerdict> {
  const doc = input.document;
  const present = !!doc && typeof doc === 'object';
  const fail = (reason: string): AttestationVerdict => ({ ok: false, present, bound: false, reason });
  try {
    const { ctx, expected, nowMs } = input;
    // an unreadable clock (NaN, Infinity, not a number) would make every window / nonce-age comparison false, i.e. pass: refuse
    if (typeof nowMs !== 'number' || !Number.isFinite(nowMs)) return fail('verifier clock is not a finite time (fail closed)');
    const trusted = new Set(input.trustedAttestorKeys);
    const skew = Number.isFinite(input.clockSkewMs) ? Math.max(0, input.clockSkewMs as number) : 0;
    const maxAge = Math.min(
      Number.isFinite(input.maxNonceAgeMs) && (input.maxNonceAgeMs as number) > 0 ? (input.maxNonceAgeMs as number) : MAX_ATTESTATION_AGE_MS,
      MAX_ATTESTATION_AGE_MS,
    );
    const hasHw = !!input.hardwareVerifier;
    let expectedBinding = '';
    let bindErr = '';
    let hw: HardwareAttestationResult | undefined;
    let envMemo: { v: ReturnType<typeof readEnvelope> } | undefined;
    const getEnv = (): ReturnType<typeof readEnvelope> => (envMemo ??= { v: readEnvelope(ctx.grant) }).v;
    const d = doc as any;
    let win: WinRes | undefined;
    const winOf = (): WinRes => (win ??= windowDecision(nowMs, skew, d.issued_at, d.expires_at));
    let identity: MeasuredIdentity | undefined;
    let agentErr: string | null = null;

    // each stage: [holds, reason-if-it-fails]; evaluated lazily, in the order given by the proved Order(), first failure wins
    const stage = (k: string): [boolean, string] => {
      switch (k) {
        case 'KPresent': return [present, 'no attestation document for this action'];
        case 'KBindingConstructible':
          try {
            expectedBinding = attestationBindingB64u(expected);
            return [true, ''];
          } catch (e) {
            bindErr = `attestation binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`;
            return [false, bindErr];
          }
        case 'KGrantRef': return [ctx?.pcactn?.grant_ref === expected.grantRef, 'attestation binding: PCActn grant_ref differs from expected grant'];
        case 'KEpoch': return [ctx?.pcactn?.attestation?.epoch === expected.epoch, 'attestation binding: PCActn attestation epoch differs from expected epoch'];
        case 'KQuote': return [ctx?.pcactn?.attestation?.quote_digest === expected.nonce, 'attestation nonce does not bind to this PCActn'];
        case 'KDocNonce': return [d.nonce === expected.nonce, 'attestation nonce does not match the server-issued nonce'];
        case 'KReqHwVerifier': return [getEnv()?.agent_binding?.require_hardware !== true || hasHw, 'agent_binding.require_hardware: no hardware verifier is configured (fail closed)'];
        case 'KReqHwMode': return [getEnv()?.agent_binding?.require_hardware !== true || d.mode === 'hardware', 'agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)'];
        case 'KHwNonceAge': {
          const r = nonceAgeReason(expected.nonceIssuedAt, nowMs, skew, maxAge);
          return [r === null, r ?? ''];
        }
        case 'KHwOk': return [true, ''];
        case 'KHwBound': return [true, ''];
        case 'KHwMeasured': return [true, ''];
        case 'KSoftMode': return [d.mode === 'software', `document mode ${String(d.mode)} needs a hardwareVerifier`];
        case 'KAttestorTrusted': return [typeof d.attestor === 'string' && trusted.has(d.attestor), 'attestor key is not trusted'];
        case 'KAlgKnown': return [resolveSigAlg(d.alg) !== null, 'attestation declares an unknown signature alg'];
        case 'KSigOk': {
          const { sig, pq_sig, ...body } = d;
          return [typeof sig === 'string' && verifyPinnedSuite(d.alg, d.attestor, d.pq_pk, attestMessage(body), { sig, pq_sig }, input as any), 'attestation signature does not verify'];
        }
        case 'KBindingPresent': return [typeof d.binding === 'string' && d.binding.length > 0, 'attestation is not bound (binding absent)'];
        case 'KBindingEq': return [d.binding === expectedBinding, 'attestation binding mismatch (holder/grant/epoch/nonce)'];
        case 'KWindowWellFormed': return [winOf() !== 'malformed', 'malformed attestation validity window'];
        case 'KNotYetValid': return [winOf() !== 'notyet', 'attestation not yet valid'];
        case 'KExpired': return [winOf() !== 'expired', 'attestation expired'];
        case 'KSoftNonceAge': {
          if (typeof expected.nonceIssuedAt !== 'number') return [true, ''];
          const r = nonceAgeReason(expected.nonceIssuedAt, nowMs, skew, maxAge);
          return [r === null, r ?? ''];
        }
        case 'KAgentBinding': {
          agentErr = matchAgentBindingVerified(identity!, getEnv()?.agent_binding);
          return [agentErr === null, agentErr ?? ''];
        }
        default: throw new Error(`unknown stage ${k}`);
      }
    };

    const order: any[] = Array.from(DF.Order(hasHw));
    let acc = none();
    let reason = '';
    for (const k of order) {
      const name = kindName(k);
      // the hardware verifier is consulted exactly once, at KHwOk, after the nonce-age stage passed
      if (name === 'KHwOk') {
        hw = await input.hardwareVerifier!.verify({ document: doc!, ctx, nowMs, expected });
      }
      if (name === 'KAgentBinding' && identity === undefined) {
        identity = hasHw ? hw!.measured! : softwareIdentity(d);
      }
      let holds: boolean;
      let why: string;
      if (name === 'KHwOk') { holds = !!hw!.ok; why = `hardware attestation rejected: ${hw!.reason ?? 'invalid'}`; }
      else if (name === 'KHwBound') { holds = hw!.bound === true; why = 'hardware verifier did not confirm report_data binding'; }
      else if (name === 'KHwMeasured') { holds = !!hw!.measured; why = 'hardware verifier returned no measured identity'; }
      else { [holds, why] = stage(name); }
      acc = DF.GateStep(acc, k, holds);
      if (acc.is_Some) { reason = why; break; }
    }
    if (acc.is_Some) return fail(reason);
    return { ok: true, present: true, bound: true, identity: identity! };
  } catch (e) {
    return fail(`attestation verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }

  function softwareIdentity(doc: any): MeasuredIdentity {
    return {
      model_id: doc.model_id,
      weights_digest: doc.weights_digest,
      runtime_measurement: doc.runtime_measurement,
      operator: doc.operator,
      ...(typeof doc.system_prompt_digest === 'string' ? { system_prompt_digest: doc.system_prompt_digest } : {}),
      ...(typeof doc.tool_manifest_digest === 'string' ? { tool_manifest_digest: doc.tool_manifest_digest } : {}),
    };
  }
}

// ================================================================================================
// D. hook (nonce single use) + the verified in-memory nonce store
// ================================================================================================
export function createAttestationVerifierProved(opts: AttestationVerifierOpts): (ctx: any) => Promise<AttestationHookResult> {
  opts = snapshotConfig(opts, { keep: ['nonceStore', 'hardwareVerifier', 'resolveDocument'] }); // freeze the configuration: later edits by the caller must not change what this verifier enforces
  const trusted = Array.isArray(opts.trustedAttestorKeys) ? opts.trustedAttestorKeys : [];
  const resolve = opts.resolveDocument ?? ((): AttestationDocument | undefined => undefined);
  const clock = opts.now ?? (() => Date.now());
  return async (ctx) => {
    const fin = (v: AttestationVerdict): AttestationHookResult => ({
      enforced: true,
      ok: v.ok,
      ...(v.reason ? { reason: v.reason } : {}),
      present: v.present,
      bound: v.bound,
    });
    try {
      const document = resolve(ctx);
      let expected: ExpectedAttestationBinding | undefined;
      if (opts.expectedBinding) {
        expected = await opts.expectedBinding(ctx);
      } else if (opts.insecure_selfDeclaredNonce === true) {
        const chain = ctx?.pcactn?.cap_chain;
        const leaf = Array.isArray(chain) && chain.length > 0 ? chain[chain.length - 1] : ctx?.grant;
        expected = {
          holderPub: typeof leaf?.holder === 'string' ? leaf.holder : '',
          grantRef: ctx?.pcactn?.grant_ref,
          epoch: ctx?.pcactn?.attestation?.epoch,
          nonce: ctx?.pcactn?.attestation?.quote_digest,
        };
      }
      if (!expected) {
        return fin({ ok: false, present: !!document, bound: false, reason: 'no server-issued attestation nonce/binding available (fail closed)' });
      }
      if (opts.insecure_selfDeclaredNonce !== true && !nonceEntropyOk(expected.nonce, opts.minNonceBytes)) {
        return fin({ ok: false, present: !!document, bound: false, reason: 'attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)' });
      }
      const verdict = await verifyAttestationProved({
        document, ctx, expected, nowMs: clock(), trustedAttestorKeys: trusted, pqPins: opts.pqPins,
        allowUnboundPq: opts.allowUnboundPq, hardwareVerifier: opts.hardwareVerifier, maxNonceAgeMs: opts.maxNonceAgeMs, clockSkewMs: opts.clockSkewMs,
      });
      const hasStore = !!opts.nonceStore;
      if (DF.NeedsConsume(verdict.ok, verdict.bound, hasStore)) {
        const consumed = await opts.nonceStore!.consume(expected.nonce);
        const out = DF.HookFinal(verdict.ok, verdict.bound, hasStore, !!consumed);
        if (!out.is_HookOk) return fin({ ok: false, present: verdict.present, bound: false, reason: 'attestation nonce already consumed (replay)' });
      }
      return fin(verdict);
    } catch (e) {
      return fin({ ok: false, present: false, bound: false, reason: `attestation verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` });
    }
  };
}

const B64U_DIGEST = /^[A-Za-z0-9_-]{43}$/;
const isRec = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
function parseHW(x: unknown): { version: number; digest: string } | undefined {
  if (!isRec(x) || typeof x['version'] !== 'number' || !Number.isSafeInteger(x['version']) || typeof x['digest'] !== 'string' || !B64U_DIGEST.test(x['digest'])) return undefined;
  return { version: x['version'], digest: x['digest'] };
}

type Fail = { ok: false; code: any; reason: string };
const afail = (code: string, reason: string): Fail => ({ ok: false, code, reason });

/** verifyAllowlistDurable whose accept / rollback / conflict decision is the proved DurableStep. */
export async function verifyAllowlistDurableProved(
  manifest: unknown,
  opts: Omit<VerifyAllowlistOptions, 'lastSeenVersion' | 'lastSeenDigest'>,
  kv: DurableKv,
): Promise<VerifyAllowlistResult> {
  try {
    const issuer = isRec(manifest) && typeof manifest['issuer'] === 'string' && manifest['issuer'].length <= 200 ? manifest['issuer'] : undefined;
    if (issuer === undefined) return afail('malformed', 'issuer must be a string');
    const key = `allowlist/${issuer}`;
    const it = new Interner();
    const raw = await kv.get(key);
    const prior = raw === undefined ? undefined : parseHW(raw);
    const read = raw === undefined ? A.KV.create_KMissing() : prior === undefined ? A.KV.create_KCorrupt() : A.KV.create_KVal(bn(prior.version), bn(it.id(prior.digest)));
    if (read.is_KCorrupt) return afail('malformed', 'persisted allowlist high-water mark is corrupt');
    const v = verifyAllowlistManifest(manifest, { ...opts, ...(prior ? { lastSeenVersion: prior.version, lastSeenDigest: prior.digest } : {}) });
    if (!v.ok) return v;
    let nowKv: any;
    const stored = await kv.update(key, (cur) => {
      const c = cur === undefined ? undefined : parseHW(cur);
      nowKv = cur === undefined ? A.KV.create_KMissing() : c === undefined ? A.KV.create_KCorrupt() : A.KV.create_KVal(bn(c.version), bn(it.id(c.digest)));
      // the proved UpdateFn (append-only: a stored version >= ours is kept as is)
      const next = DF.UpdateFn(nowKv, bn(v.version), bn(it.id(v.digest)));
      return next.is_KVal && !next.equals(nowKv) ? { version: v.version, digest: v.digest } : undefined;
    });
    if (nowKv === undefined) {
      // The DurableKv contract only promises "returns the value now stored"; a store may answer without running the
      // updater (a remote CAS that saw a newer / equal record, a cache). Our updater wrote nothing, so the returned record
      // IS the record at update time: decide on it with the same proved step. Nothing (or nothing parseable) stored
      // means our acceptance was never recorded: fail closed as a rollback, never accept unpersisted.
      const s = stored === undefined ? undefined : parseHW(stored);
      if (s === undefined) return afail('rollback', 'a newer manifest was accepted concurrently');
      nowKv = A.KV.create_KVal(bn(s.version), bn(it.id(s.digest)));
    }
    const r = DF.DurableStep(read, nowKv, true, bn(v.version), bn(it.id(v.digest)));
    const out = r[0];
    if (out.is_DAccept) return v;
    if (out.is_DConflict) return afail('conflict', 'same version as the stored high-water mark but a different body');
    return afail('rollback', 'a newer manifest was accepted concurrently');
  } catch (e) {
    return afail('malformed', e instanceof Error ? e.message : 'durable verification error');
  }
}

const B64U43 = /^[A-Za-z0-9_-]{43}$/;
function validEntry(e: unknown): e is AllowlistAnchorEntry {
  if (typeof e !== 'object' || e === null) return false;
  const r = e as Record<string, unknown>;
  return (
    Object.keys(r).length === 3 &&
    typeof r['issuer'] === 'string' && r['issuer'].length > 0 && r['issuer'].length <= 200 &&
    typeof r['version'] === 'number' && Number.isSafeInteger(r['version']) && r['version'] >= 1 &&
    typeof r['digest'] === 'string' && B64U43.test(r['digest'])
  );
}
const MAX_FEED = 100_000;
const DAY = 86_400_000;

/** verifyAllowlistAnchored with the cache, freshness and feed-scan decisions made by the proved CacheStage / HeadFreshness / AnchorScan. */
export function verifyAllowlistAnchoredProved(
  verified: Extract<VerifyAllowlistResult, { ok: true }>,
  evidence: AllowlistAnchorEvidence | undefined,
  opts: VerifyAnchoredOptions,
): AnchoredResult {
  const no = (code: any, reason: string): AnchoredResult => ({ ok: false, code, reason });
  try {
    if (evidence === undefined || evidence === null || typeof evidence !== 'object' || evidence.proof === undefined || evidence.head === undefined || !Array.isArray(evidence.entries)) {
      return no('missing-proof', 'no anchor evidence (head + entries + inclusion proof) supplied');
    }
    const { trust } = opts;
    if (!Number.isSafeInteger(opts.nowMs)) return no('bad-head', 'nowMs must be an integer');
    const head = evidence.head;
    if (!verifyTreeHead(head, trust.logKey, trust.witnesses, trust)) return no('bad-head', 'tree head is not signed by the pinned log key (or lacks the required witness cosignatures)');
    if (head.instance_id !== trust.instanceId || head.principal !== trust.principal) return no('bad-head', 'tree head is for a different log');
    // option validity is a glue fact; the proved HeadFreshness rejects (HeadBadOptions) before any comparison
    const skewOk = opts.clockSkewMs === undefined || (typeof opts.clockSkewMs === 'number' && Number.isFinite(opts.clockSkewMs));
    const ageOk = opts.maxHeadAgeMs === undefined || (typeof opts.maxHeadAgeMs === 'number' && Number.isFinite(opts.maxHeadAgeMs));
    // (the numeric operands are irrelevant once the options are invalid: HeadBadOptions is decided first)
    if (DF.HeadFreshness(skewOk && ageOk, bn(0), bn(0), bn(0), bn(0)).is_HeadBadOptions) {
      return no('bad-head', skewOk ? 'maxHeadAgeMs must be a finite number' : 'clockSkewMs must be a finite number');
    }
    const skew = Math.max(0, opts.clockSkewMs ?? 60_000);
    const maxAge = opts.maxHeadAgeMs ?? DAY;
    // freshness: proved arithmetic when integral. Non-integral or non-finite config falls back to the production comparisons
    // (NaN there disables both checks: see the NaN finding in the docs).
    const ageInt = Number.isSafeInteger(head.timestamp) && Number.isFinite(skew) && Number.isFinite(maxAge) && Math.abs(maxAge) < 2 ** 52;
    if (!Number.isSafeInteger(head.timestamp)) return no('stale-head', 'tree head is timestamped in the future');
    if (ageInt) {
      const r = DF.HeadFreshness(true, bn(head.timestamp), bn(opts.nowMs), bn(Math.floor(skew)), bn(Math.floor(maxAge)));
      if (r.is_HeadFuture) return no('stale-head', 'tree head is timestamped in the future');
      if (r.is_HeadStale) return no('stale-head', `tree head is older than maxHeadAgeMs (${maxAge})`);
    } else {
      if (head.timestamp > opts.nowMs + skew) return no('stale-head', 'tree head is timestamped in the future');
      if (opts.nowMs - head.timestamp > maxAge) return no('stale-head', `tree head is older than maxHeadAgeMs (${maxAge})`);
    }

    const cached = opts.cachedHead;
    if (cached !== undefined) {
      if (!verifyTreeHead(cached, trust.logKey, trust.witnesses, trust) || cached.instance_id !== trust.instanceId || cached.principal !== trust.principal) {
        return no('bad-cache', 'the cached head does not verify under the pinned log key');
      }
      const cs = DF.CacheStage(true, bn(head.size), bn(cached.size), head.root === cached.root);
      if (cs.is_CacheRollback) return no('log-rollback', `head size ${head.size} < cached ${cached.size}: the log shrank`);
      if (cs.is_CacheSplitView) return no('split-view', 'two different roots at the same size: split view / fork');
      if (cs.is_CacheNeedConsistency) {
        const c = evidence.consistency;
        if (c === undefined || !verifyHeadConsistency(cached, head, c, trust.logKey, trust.witnesses, trust)) {
          return no('inconsistent-with-cache', 'no valid consistency proof from the cached head: forked or truncated log');
        }
      }
    }

    const entries = evidence.entries;
    if (entries.length > MAX_FEED || entries.length !== head.size || !entries.every(validEntry)) return no('feed-mismatch', 'entries do not match the signed tree size');
    const commits = entries.map(allowlistAnchorCommit);
    if (ledgerRootOf(commits) !== head.root) return no('feed-mismatch', 'entries do not reproduce the signed root');

    const it = new Interner();
    const toE = (e: AllowlistAnchorEntry): any => A.AEntry.create_AEntry(bn(it.id(e.issuer)), bn(e.version), bn(it.id(e.digest)));
    const mine: AllowlistAnchorEntry = { issuer: verified.issuer, version: verified.version, digest: verified.digest };
    // production scans (and may report log-conflict) BEFORE the proof checks, but the proof checks come before rollback / not-anchored
    const issuerEntries = entries.filter((e) => e.issuer === verified.issuer);
    // The extracted AnchorScan is spec-shaped: FeedConflict is a doubly-nested BigNumber quantifier over the WHOLE feed (|es|^2:
    // 10^10 steps at MAX_FEED, a synchronous stall no test timeout can interrupt) and Highest recurses once per entry (a stack
    // overflow on a large single-issuer feed). Every one of its three clauses only looks at entries whose issuer is
    // mine.issuer and only asks EXISTENCE questions, so it is decided on a witness subset W of those entries that answers each
    // question exactly as the full feed does, built in one linear pass:
    //   FeedConflict(es) <=> FeedConflict(W): W holds the first pair (same version, other digest) if one exists, and every
    //                                         other member of W is a feed entry, so W can conflict only if es does;
    //   Highest(es)      == Highest(W):     W holds an entry of the highest version (and only feed entries);
    //   exists mine      <=> mine in W:     W holds mine whenever the feed does.
    const firstDigest = new Map<number, string>();
    const witness: AllowlistAnchorEntry[] = [];
    let top: AllowlistAnchorEntry | undefined;
    let conflictPair = false;
    for (const e of issuerEntries) {
      if (top === undefined || e.version > top.version) top = e;
      const d0 = firstDigest.get(e.version);
      if (d0 === undefined) firstDigest.set(e.version, e.digest);
      else if (!conflictPair && d0 !== e.digest) {
        conflictPair = true;
        witness.push({ issuer: e.issuer, version: e.version, digest: d0 }, e);
      }
    }
    if (top !== undefined) witness.push(top);
    if (issuerEntries.some((e) => e.version === mine.version && e.digest === mine.digest)) witness.push(mine);
    const es = seqOf(witness.map(toE));
    const scan = DF.AnchorScan(es, toE(mine));
    const conflictFirst = scan.is_Some && scan.dtor_v.is_ALogConflict;
    if (conflictFirst) {
      const byVersion = new Map<number, string>();
      for (const e of issuerEntries) {
        const prior = byVersion.get(e.version);
        if (prior !== undefined && prior !== e.digest) return no('log-conflict', `log anchors two different digests for version ${e.version}`);
        byVersion.set(e.version, e.digest);
      }
    }
    const highest = issuerEntries.reduce((m, e) => Math.max(m, e.version), 0);
    const myCommit = allowlistAnchorCommit(mine);
    if (evidence.proof.size !== head.size) return no('bad-proof', 'inclusion proof size does not match the signed head size');
    if (!verifyLedgerInclusion(head.root, evidence.proof, myCommit)) return no('bad-proof', 'inclusion proof does not place this manifest under the signed root');
    if (scan.is_Some && scan.dtor_v.is_AAnchoredRollback) return no('anchored-rollback', `manifest version ${verified.version} < highest anchored ${highest} for '${verified.issuer}'`);
    if (scan.is_Some && scan.dtor_v.is_ANotAnchored) return no('not-anchored', 'this manifest digest is not the one anchored for its version');
    return { ok: true, issuer: verified.issuer, version: verified.version, digest: verified.digest, highestAnchoredVersion: highest, head };
  } catch (e) {
    return no('bad-head', e instanceof Error ? e.message : 'anchor verification error');
  }
}
