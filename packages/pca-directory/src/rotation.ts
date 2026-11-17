/**
 * Log key rotation: a signed, witnessed key-transition statement.
 *
 * A log that has to change its signing key publishes a transition: `{ from, to, at_size, at_root }`, signed by the OLD key
 * (it hands over), signed by the NEW key (it is held by whoever publishes this), and cosigned by the trusted witnesses over the
 * transition itself, in the existing C2SP cosignature format. A relying party that pinned the old key accepts heads from the new
 * key by following a chain of such transitions; a transition without a witness quorum, with a bad signature, for another log, out of
 * sequence or not starting at a key it trusts is ignored. After a transition, a head signed by the old key that is larger than
 * `at_size` is refused: the old key has retired, so such a head means the old key is in someone else's hands.
 *
 * The witness cosignature reuses `cosignTreeHead` over a synthetic head whose principal names the transition, so it cannot be
 * replayed as a cosignature of a real tree head (the log's principal may not start with `TRANSITION_PRINCIPAL_PREFIX`).
 */
import { b64u, canonicalBytesStrict, publicKeyOf, sha256, sign, utf8, verifyB64u } from '@atlasauth/pca';
import type { PqPinPolicy } from '@atlasauth/pca';
import {
  cosignTreeHead,
  verifyHeadConsistency,
  verifyLedgerConsistency,
  verifyWitnessCosignatures,
  type ConsistencyProof,
  type SignedTreeHead,
  type WitnessCosignature,
  type WitnessPolicy,
} from '@atlasauth/pca/ext/ledger';

export const TRANSITION_PRINCIPAL_PREFIX = 'directory-key-transition:';
const DOMAIN = 'atlas-pca/directory-key-transition/v1\0';
export const MAX_TRANSITION_CHAIN = 8;

export interface KeyTransition {
  typ: 'atlas-pca/directory-key-transition';
  ver: 1;
  /** The log id and the STH scope the keys sign under. */
  log: string;
  instance_id: string;
  principal: string;
  /** 1 for the first rotation of a log, then +1 each time. */
  seq: number;
  from: string;
  to: string;
  /** The size and root of the last head the old key signed. */
  at_size: number;
  at_root: string;
  iat: number;
}

export interface SignedKeyTransition extends KeyTransition {
  sig_old: string;
  sig_new: string;
  /** Witness cosignatures of the transition (see `cosignTransition`). */
  witnesses?: WitnessCosignature[];
}

const body = (t: KeyTransition): KeyTransition => ({
  typ: t.typ,
  ver: t.ver,
  log: t.log,
  instance_id: t.instance_id,
  principal: t.principal,
  seq: t.seq,
  from: t.from,
  to: t.to,
  at_size: t.at_size,
  at_root: t.at_root,
  iat: t.iat,
});

const message = (t: KeyTransition, role: 'old' | 'new'): Uint8Array => {
  const p = utf8(DOMAIN);
  const b = canonicalBytesStrict({ role, body: body(t) });
  const m = new Uint8Array(p.length + b.length);
  m.set(p);
  m.set(b, p.length);
  return m;
};

/** Both keys sign: the old one hands over, the new one shows it is held. The caller must have the old key's last head (size, root). */
export function signKeyTransition(o: {
  log: string;
  instanceId: string;
  principal: string;
  seq: number;
  oldSecret: Uint8Array;
  newSecret: Uint8Array;
  atSize: number;
  atRoot: string;
  iat: number;
}): SignedKeyTransition {
  const t: KeyTransition = {
    typ: 'atlas-pca/directory-key-transition',
    ver: 1,
    log: o.log,
    instance_id: o.instanceId,
    principal: o.principal,
    seq: o.seq,
    from: b64u(publicKeyOf(o.oldSecret)),
    to: b64u(publicKeyOf(o.newSecret)),
    at_size: o.atSize,
    at_root: o.atRoot,
    iat: o.iat,
  };
  return { ...t, sig_old: b64u(sign(o.oldSecret, message(t, 'old'))), sig_new: b64u(sign(o.newSecret, message(t, 'new'))) };
}

/** The synthetic head a witness cosigns for a transition: it commits to the whole statement and names it in the principal. */
export function transitionHead(t: KeyTransition): Pick<SignedTreeHead, 'instance_id' | 'principal' | 'size' | 'root' | 'prev_root'> {
  return {
    instance_id: t.instance_id,
    principal: `${TRANSITION_PRINCIPAL_PREFIX}${t.principal}`,
    size: t.at_size,
    root: b64u(sha256(message(t, 'old'))),
    prev_root: t.at_root,
  };
}

/** A witness cosigns the transition with its own key (a witness first checks it has cosigned the `at` head: see `Witness.cosignTransition`). */
export const cosignTransition = (t: KeyTransition, witnessSecret: Uint8Array): WitnessCosignature => cosignTreeHead(transitionHead(t), witnessSecret);

/** Signatures and shape only (no witnesses). Never throws. */
export function transitionSignaturesOk(t: unknown): t is SignedKeyTransition {
  try {
    const x = t as Partial<SignedKeyTransition> | null;
    if (!x || x.typ !== 'atlas-pca/directory-key-transition' || x.ver !== 1) return false;
    for (const k of ['log', 'instance_id', 'principal', 'from', 'to', 'at_root', 'sig_old', 'sig_new'] as const) if (typeof x[k] !== 'string' || x[k]!.length === 0) return false;
    if (!Number.isSafeInteger(x.seq) || x.seq! < 1 || !Number.isSafeInteger(x.at_size) || x.at_size! < 0 || !Number.isSafeInteger(x.iat)) return false;
    if (x.from === x.to) return false;
    const tt = x as SignedKeyTransition;
    return verifyB64u(tt.from, message(tt, 'old'), tt.sig_old) && verifyB64u(tt.to, message(tt, 'new'), tt.sig_new);
  } catch {
    return false;
  }
}

/** Signatures plus a witness quorum over the transition. A quorum of zero is never enough: a rotation must be witnessed. */
export function verifyKeyTransition(t: unknown, witnesses: WitnessPolicy): t is SignedKeyTransition {
  try {
    if (!transitionSignaturesOk(t) || !(witnesses?.threshold >= 1)) return false;
    const head = transitionHead(t);
    return verifyWitnessCosignatures({ ...head, guardian: t.to, sig: '', timestamp: t.iat, witnesses: t.witnesses } as SignedTreeHead, witnesses);
  } catch {
    return false;
  }
}

export type KeyResolution = { ok: true; key: string; chain: SignedKeyTransition[] } | { ok: false; reason: 'no_chain' | 'chain_too_long' };

/**
 * The key a head is checked against: `pinned` itself, or the end of a chain of valid, witnessed, consecutive transitions from
 * `pinned` to `signer`. Transitions for another log (instance, principal) are ignored.
 */
export function resolveLogKey(
  pinned: string,
  signer: string,
  transitions: readonly unknown[] | undefined,
  witnesses: WitnessPolicy,
  scope: { instanceId?: string; principal?: string } = {},
): KeyResolution {
  if (signer === pinned) return { ok: true, key: pinned, chain: [] };
  const valid = (transitions ?? []).filter(
    (t): t is SignedKeyTransition =>
      verifyKeyTransition(t, witnesses) &&
      (scope.instanceId === undefined || t.instance_id === scope.instanceId) &&
      (scope.principal === undefined || t.principal === scope.principal),
  );
  const chain: SignedKeyTransition[] = [];
  let cur = pinned;
  let seq = 0;
  while (cur !== signer) {
    if (chain.length >= MAX_TRANSITION_CHAIN) return { ok: false, reason: 'chain_too_long' };
    const next = valid.find((t) => t.from === cur && (seq === 0 || t.seq === seq + 1) && !chain.some((c) => c.to === t.to));
    if (!next) return { ok: false, reason: 'no_chain' };
    chain.push(next);
    seq = next.seq;
    cur = next.to;
  }
  return { ok: true, key: cur, chain };
}

/** The size above which a head signed by `key` is refused because a valid transition retired it, or undefined when it has not retired. */
export function retiredAtSize(
  key: string,
  transitions: readonly unknown[] | undefined,
  witnesses: WitnessPolicy,
  scope: { instanceId?: string; principal?: string } = {},
): number | undefined {
  let at: number | undefined;
  for (const t of transitions ?? []) {
    if (!verifyKeyTransition(t, witnesses) || t.from !== key) continue;
    if ((scope.instanceId !== undefined && t.instance_id !== scope.instanceId) || (scope.principal !== undefined && t.principal !== scope.principal)) continue;
    at = at === undefined ? t.at_size : Math.min(at, t.at_size);
  }
  return at;
}

/**
 * Does `newer` extend `older`? Same signer: the ledger's own check (signatures, signed `prev_root` link, RFC 9162 path). Different
 * signers (a rotation between them): the caller has already resolved both keys through a witnessed transition chain, so this checks
 * scope, sizes and the consistency path directly.
 */
export function headExtends(older: SignedTreeHead, newer: SignedTreeHead, proof: ConsistencyProof, pins?: PqPinPolicy): boolean {
  if (older.guardian === newer.guardian) return verifyHeadConsistency(older, newer, proof, older.guardian, undefined, pins);
  return (
    older.instance_id === newer.instance_id &&
    older.principal === newer.principal &&
    proof?.oldSize === older.size &&
    proof?.newSize === newer.size &&
    verifyLedgerConsistency(older.root, newer.root, proof)
  );
}
