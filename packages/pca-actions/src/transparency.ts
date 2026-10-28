// transparency.ts - append a signed pack to a SCITT transparency log (RFC 9943) and verify the receipt. The statement is a COSE
// Signed Statement over {ns, version, digest, root, prev}; the receipt is the log's signed inclusion proof. A verifier that holds
// the pinned log key and tree root can then show "this exact pack version was published" to a third party, and two different
// packs at one version can be proved by two receipts (equivocation).

import { signStatement, statementPayload, verifyReceipt, type CoseAlg } from '@atlasauth/pca-scitt';
// the in-memory log lives under /testing since the durable log became the production one
import { registerStatement, type TransparencyService } from '@atlasauth/pca-scitt/testing';
import { canonicalBytes } from '@atlasauth/pca';
import type { KeyObject } from 'node:crypto';
import { packDigest, type ActionPack } from './pack';

export const PACK_STATEMENT_CONTENT_TYPE = 'application/pca-action-pack+json';

/** The payload the registry signs into the log (small: the digest, not the pack). */
export const packStatementPayload = (p: ActionPack) => ({ v: 1, kind: 'pca-action-pack-statement', ns: p.ns, version: p.version, digest: packDigest(p), root: p.root, prev: p.prev });

export interface PackLogEntry {
  statement: Uint8Array;
  receipt: Uint8Array;
  index: number;
  root: string;
}

/** Sign the pack's statement with the registry's COSE key and register it. */
export function appendPackToLog(pack: ActionPack, service: TransparencyService, signer: { alg: CoseAlg; key: KeyObject; issuer: string }): PackLogEntry {
  const statement = signStatement(packStatementPayload(pack), { alg: signer.alg, key: signer.key, issuer: signer.issuer, subject: `${pack.ns}@${pack.version}`, contentType: PACK_STATEMENT_CONTENT_TYPE });
  const r = registerStatement(statement, service);
  return { statement, receipt: r.receipt, index: r.index, root: r.root };
}

/** Does `entry` prove `pack` is in the log? The statement must be the pack's own and signed by the registry, the receipt by the log. */
export function verifyPackLogEntry(pack: ActionPack, entry: { statement: Uint8Array; receipt: Uint8Array }, keys: { registry: KeyObject; log: KeyObject }, treeRoot?: string): boolean {
  try {
    return verifyReceipt(entry.receipt, entry.statement, { verificationKey: keys.log, statementKey: keys.registry, ...(treeRoot !== undefined ? { treeRoot } : {}) }) && statementIsFor(pack, entry.statement);
  } catch {
    return false;
  }
}

function statementIsFor(pack: ActionPack, statement: Uint8Array): boolean {
  const got = statementPayload(statement);
  const want = canonicalBytes(packStatementPayload(pack));
  return got.length === want.length && got.every((b, i) => b === want[i]);
}
