// registry.ts - the verifier's view of a registry: the highest pack version and digest accepted per namespace, so that a
// rollback (an older signed pack replayed), a fork (two packs at one version), or a chain gap (a pack that does not extend the
// accepted one) is refused. State is per verifier; `snapshot`/`restore` persist the part that matters across restarts.

import type { ActionSchemaKey } from '@atlasauth/pca/ext/intent';
import { compareVersions, packDigest, verifyPack, verifyUpgrade, type ActionPack, type PackShard } from './pack';
import type { Registry } from './traits';
import { CORE_REGISTRY } from './core-traits';

export type AcceptCode = 'bad_pack' | 'rollback' | 'fork' | 'chain_gap' | 'bad_upgrade';
export type AcceptResult = { ok: true; status: 'first' | 'same' | 'upgrade' } | { ok: false; code: AcceptCode; reason: string };
export interface TrackedPack {
  ns: string;
  version: string;
  digest: string;
}

export class PackTracker {
  private readonly seen = new Map<string, { version: string; digest: string; pack?: ActionPack; shards?: Readonly<Record<string, PackShard>> }>();
  constructor(
    private readonly keys: readonly ActionSchemaKey[],
    private readonly opts: { reg?: Registry; keepContent?: boolean } = {},
  ) {}

  /**
   * Accept `pack` iff it verifies and extends what this verifier accepted for its namespace: the same pack again is `same`; a higher
   * version whose `prev` is the accepted digest is an `upgrade` (and, when the accepted content is held, its signed evolution must be
   * exactly the computed change); a version not above the accepted one is a `rollback` (or a `fork` when the version is equal and the
   * digest differs); a higher version that does not chain is a `chain_gap`. The first pack of a namespace is trusted on first use.
   */
  accept(pack: ActionPack, shards?: Readonly<Record<string, PackShard>>): AcceptResult {
    const v = verifyPack(pack, this.keys, { ...(shards ? { shards } : {}), reg: this.opts.reg ?? CORE_REGISTRY });
    if (!v.ok) return { ok: false, code: 'bad_pack', reason: v.reason };
    const cur = this.seen.get(pack.ns);
    const keep = this.opts.keepContent !== false;
    const record = () => this.seen.set(pack.ns, { version: pack.version, digest: v.digest, ...(keep ? { pack, ...(shards ? { shards } : {}) } : {}) });
    if (cur === undefined) {
      record();
      return { ok: true, status: 'first' };
    }
    if (cur.digest === v.digest) return { ok: true, status: 'same' };
    const c = compareVersions(pack.version, cur.version);
    if (c < 0) return { ok: false, code: 'rollback', reason: `version ${pack.version} is older than the accepted ${cur.version}` };
    if (c === 0) return { ok: false, code: 'fork', reason: `two different packs claim version ${pack.version}` };
    if (pack.prev !== cur.digest) return { ok: false, code: 'chain_gap', reason: 'prev does not name the accepted pack' };
    if (cur.pack !== undefined) {
      const u = verifyUpgrade(cur.pack, pack, this.keys, { ...(cur.shards ? { prevShards: cur.shards } : {}), ...(shards ? { shards } : {}), reg: this.opts.reg ?? CORE_REGISTRY });
      if (!u.ok) return { ok: false, code: 'bad_upgrade', reason: u.reason };
    }
    record();
    return { ok: true, status: 'upgrade' };
  }

  /** `{ns, version, digest}` per namespace (the monotone state worth persisting). */
  snapshot(): TrackedPack[] {
    return [...this.seen].map(([ns, s]) => ({ ns, version: s.version, digest: s.digest })).sort((a, b) => (a.ns < b.ns ? -1 : 1));
  }
  /** Restore a snapshot (content is not restored: the first upgrade after a restore is checked for chain and version only). */
  restore(s: readonly TrackedPack[]): void {
    for (const t of s) this.seen.set(t.ns, { version: t.version, digest: t.digest });
  }
}

export { packDigest };
