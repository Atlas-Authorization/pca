/**
 * The log's HTTP surface as a plain function: method + path + query + JSON body in, status + JSON out. `serveLog` (node) and any
 * other framework adapter wrap it, so the wire format is defined in one place.
 *
 *   GET  /sth                     the signed tree head (best cosigned head when `minCosigs` is set)
 *   GET  /consistency?from&to     RFC 9162 consistency proof
 *   GET  /entries?from&limit      the monitor feed
 *   GET  /key-transitions         the witnessed key transitions, oldest first
 *   GET  /entries/:index          one entry with its inclusion proof and head
 *   GET  /proof?digest            the entry for a passport digest, with proof and head
 *   GET  /status?subject          every entry for a subject reference, each with a proof against one head
 *   POST /entries                 submit a registration or a revocation
 *   GET  /rotation                the key transition awaiting witness cosignatures (404 when none)
 *   POST /rotation/cosignatures   a witness posts its cosignature of that transition
 *   POST /cosignatures            a witness posts its cosignature
 */
import { entryView, memoryLogClient } from './client';
import type { DirectoryLog, SubmitReason, SubmitRequest } from './log';
import type { WitnessCosignature } from '@atlasauth/pca/ext/ledger';

export interface RouteRequest {
  method: string;
  path: string;
  query: Record<string, string | undefined>;
  body?: unknown;
  /** Flood-accounting id for the caller (an IP, an API key id). */
  submitter: string;
}
export interface RouteResponse {
  status: number;
  body: unknown;
}

export interface RouteOptions {
  /** Cosignatures a served head should carry when one is available. */
  minCosigs?: number;
}

const REFUSAL_STATUS: Record<SubmitReason, number> = {
  malformed: 400,
  rate_limited: 429,
  log_full: 507,
  mode_not_allowed: 422,
  issuer_not_allowed: 403,
  passport_invalid: 422,
  bad_pop: 422,
  revoked: 409,
  too_many_entries: 429,
  bad_revocation: 422,
  unknown_passport: 404,
  revocation_mismatch: 422,
  conflict: 409,
};

export const submitRefusalStatus = (r: SubmitReason): number => REFUSAL_STATUS[r];

const int = (v: string | undefined, d: number): number => (v === undefined ? d : /^\d{1,15}$/.test(v) ? Number(v) : Number.NaN);
const err = (status: number, error: string): RouteResponse => ({ status, body: { error } });

export function directoryRoutes(log: DirectoryLog, o: RouteOptions = {}): (req: RouteRequest) => Promise<RouteResponse> {
  const client = memoryLogClient(log, { minCosigs: o.minCosigs ?? 0 });
  return async (req) => {
    try {
      const path = req.path.replace(/\/+$/, '') || '/';
      if (req.method === 'GET') {
        if (path === '/sth') return { status: 200, body: { object: 'pca_directory_sth', log: log.id, guardian_public_key: log.publicKey, signed_tree_head: await client.sth() } };
        if (path === '/consistency') {
          const from = int(req.query.from, Number.NaN);
          const to = req.query.to === undefined ? undefined : int(req.query.to, Number.NaN);
          if (Number.isNaN(from) || (to !== undefined && Number.isNaN(to))) return err(400, 'from and to must be non-negative integers');
          const proof = await log.consistency(from, to);
          return proof ? { status: 200, body: { object: 'pca_directory_consistency', consistency_proof: proof } } : err(400, 'invalid sizes');
        }
        if (path === '/rotation') {
          const t = log.pendingTransition();
          return t ? { status: 200, body: { object: 'pca_directory_rotation', transition: t } } : err(404, 'no rotation in progress');
        }
        if (path === '/key-transitions') return { status: 200, body: { object: 'list', data: await log.transitions() } };
        if (path === '/entries') {
          const from = int(req.query.from, 0);
          const limit = int(req.query.limit, 100);
          if (Number.isNaN(from) || Number.isNaN(limit) || limit < 1) return err(400, 'from and limit must be positive integers');
          return { status: 200, body: { object: 'list', data: (await log.entries(from, limit)).map(entryView) } };
        }
        const one = /^\/entries\/(\d{1,15})$/.exec(path);
        if (one) {
          const row = await log.entry(Number(one[1]));
          if (!row) return err(404, 'no such entry');
          const sth = await log.cosignedSth(o.minCosigs ?? 0, row.index + 1);
          const proof = await log.inclusion(row.index, sth.size);
          return proof ? { status: 200, body: { object: 'pca_directory_entry', entry: entryView(row), proof, sth } } : err(404, 'no such entry');
        }
        if (path === '/proof') {
          const digest = req.query.digest;
          if (!digest || digest.length > 128) return err(400, 'digest is required');
          const p = await client.inclusion(digest);
          return p ? { status: 200, body: { object: 'pca_directory_entry', ...p } } : err(404, 'not listed');
        }
        if (path === '/status') {
          const subject = req.query.subject;
          if (!subject || subject.length > 2048) return err(400, 'subject is required');
          return { status: 200, body: { object: 'pca_directory_status', ...(await client.status(subject)) } };
        }
        return err(404, 'not found');
      }
      if (req.method === 'POST') {
        if (path === '/entries') {
          const b = req.body as Record<string, unknown> | null;
          if (!b || typeof b !== 'object' || Array.isArray(b)) return err(400, 'a JSON object body is required');
          const known = new Set(['passport', 'pop', 'mode', 'revocation']);
          if (Object.keys(b).some((k) => !known.has(k))) return err(400, 'unknown field');
          const r = await log.submit(b as unknown as SubmitRequest, req.submitter);
          if (!r.ok) return { status: REFUSAL_STATUS[r.reason], body: { error: r.reason, ...(r.detail ? { detail: r.detail } : {}) } };
          return { status: r.created ? 201 : 200, body: { object: 'pca_directory_submission', created: r.created, index: r.index, commit: r.commit, entry: r.entry } };
        }
        if (path === '/rotation/cosignatures') {
          const b = req.body as { cosignature?: unknown } | null;
          if (!b || !b.cosignature || typeof b.cosignature !== 'object') return err(400, 'cosignature is required');
          return (await log.rotationCosign(b.cosignature as WitnessCosignature)) ? { status: 200, body: { object: 'pca_directory_cosignature', accepted: true } } : err(422, 'cosignature refused');
        }
        if (path === '/cosignatures') {
          const b = req.body as { size?: unknown; root?: unknown; cosignature?: unknown } | null;
          if (!b || !Number.isSafeInteger(b.size) || typeof b.root !== 'string' || !b.cosignature || typeof b.cosignature !== 'object') return err(400, 'size, root and cosignature are required');
          const ok = await log.addCosignature(b.size as number, b.root, b.cosignature as WitnessCosignature);
          return ok ? { status: 200, body: { object: 'pca_directory_cosignature', accepted: true } } : err(422, 'cosignature refused');
        }
      }
      return err(404, 'not found');
    } catch {
      return err(500, 'internal error');
    }
  };
}
