/**
 * `pca autopilot observe|propose|verify|review|amend`. The pca CLI hands argv here; the file system and the clock come in
 * through `io`, so the whole command surface is testable without touching a disk.
 */
import { unb64u, b64u, publicKeyOf } from '@atlasauth/pca';
import { amend, tighten } from './continuous';
import { ingestText } from './ingest';
import { summarize } from './review';
import { issueGrant, signApproval } from './signoff';
import { propose } from './synth';
import { verifyProposal, type Report } from './verify';
import type { IngestOptions, Proposal, SynthOptions, TraceSet } from './types';

export interface AutopilotIo {
  read(path: string): string;
  write(path: string, data: string): void;
  now(): number;
}

export const AUTOPILOT_USAGE = `pca autopilot — learn the tightest grant from what an agent actually did; a human signs it once

  pca autopilot observe <log|-> [--format auto|receipts|otel|jsonl] [--max N] [--params observed-params.jsonl] [--trusted-actors a,b] [--out autopilot.traces.json]
      Read an audit log (receipts), OpenTelemetry spans or JSONL into a normalized trace set. Lists sensitive actions.
      --params adds the proxy's observed-parameters log so amounts can be learned from receipts.
  pca autopilot propose <traces.json> [--tenant T] [--margin 0.2] [--min-distinct 3] [--ttl-days 30] [--window-secs 3600]
                        [--confirm id,id] [--now MS] [--out autopilot.proposal.json]
      Synthesize the least-privilege grant, policy and budget. Sensitive and denied actions stay out unless confirmed by id.
  pca autopilot verify <proposal.json> <traces.json> [--existing policy.json] [--out autopilot.report.json]
      Replay every trace through the verifier, report excess authority, lint, and diff against the policy in force. Exit 1 on failure.
  pca autopilot review <proposal.json> <report.json> [--reviewer-key K|@file --yes] [--out autopilot.approval.json]
                       [--holder PUBKEY --goal TEXT --grant-out autopilot.grant.json]
      Print the plain-language summary. With --yes, sign it (the key is the pinned reviewer); with --holder and --goal also mint the grant.
  pca autopilot amend <proposal.json> <traces.json> [--min-repeats 3] [--confirm id,id] [--out ...]
  pca autopilot amend <proposal.json> <traces.json> --unused-days N [--observed-from MS] [--out ...]
      Propose the minimal widening for denied-but-legitimate actions, or tighten what went unused. Both need a fresh review.

Nothing here grants authority. A proposal becomes a grant only through a signed review.
`;

interface Args { pos: string[]; flags: Record<string, string> }
const BOOL = new Set(['yes']);

function parse(argv: string[]): Args {
  const pos: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith('--')) { pos.push(a); continue; }
    const body = a.slice(2);
    const eq = body.indexOf('=');
    if (eq >= 0) flags[body.slice(0, eq)] = body.slice(eq + 1);
    else if (!BOOL.has(body) && argv[i + 1] !== undefined && !argv[i + 1]!.startsWith('--')) flags[body] = argv[++i]!;
    else flags[body] = '';
  }
  return { pos, flags };
}

const num = (f: Record<string, string>, k: string): number | undefined => {
  if (f[k] === undefined) return undefined;
  const n = Number(f[k]);
  if (f[k] === '' || !Number.isFinite(n)) throw new Error(`--${k} must be a finite number`);
  return n;
};
const list = (s: string | undefined): string[] | undefined => (s === undefined ? undefined : s.split(',').map((x) => x.trim()).filter(Boolean));
const json = <T>(io: AutopilotIo, path: string): T => JSON.parse(io.read(path)) as T;

function secret(io: AutopilotIo, v: string | undefined): Uint8Array {
  if (v === undefined || v === '') throw new Error('--reviewer-key is required to sign');
  const k = unb64u((v.startsWith('@') ? io.read(v.slice(1)) : v).trim());
  if (k.length !== 32) throw new Error('--reviewer-key must be a 32-byte Ed25519 secret as base64url');
  return k;
}

function synthOpts(f: Record<string, string>, io: AutopilotIo): SynthOptions {
  const ttl = num(f, 'ttl-days');
  return {
    ...(f.tenant ? { tenant: f.tenant } : {}),
    ...(num(f, 'margin') !== undefined ? { margin: num(f, 'margin')! } : {}),
    ...(num(f, 'min-distinct') !== undefined ? { minDistinct: num(f, 'min-distinct')! } : {}),
    ...(num(f, 'window-secs') !== undefined ? { windowSecs: num(f, 'window-secs')! } : {}),
    ...(ttl !== undefined ? { ttlMs: ttl * 86_400_000 } : {}),
    ...(f.confirm ? { confirmed: list(f.confirm)! } : {}),
    now: num(f, 'now') ?? io.now(),
  };
}

/** Run one `autopilot` subcommand. `ok:false` maps to a non-zero exit. */
export async function runAutopilot(argv: string[], io: AutopilotIo): Promise<{ ok: boolean; text: string }> {
  const [sub, ...rest] = argv;
  if (sub === undefined || sub === '--help' || sub === '-h' || sub === 'help') return { ok: true, text: AUTOPILOT_USAGE };
  const { pos, flags: f } = parse(rest);
  try {
    switch (sub) {
      case 'observe': {
        if (pos[0] === undefined) throw new Error("observe: expected a log file or '-'");
        const fmt = (f.format ?? 'auto') as 'auto' | 'receipts' | 'otel' | 'jsonl';
        if (!['auto', 'receipts', 'otel', 'jsonl'].includes(fmt)) throw new Error('--format must be auto, receipts, otel or jsonl');
        const o: IngestOptions = { ...(num(f, 'max') !== undefined ? { maxTraces: num(f, 'max')! } : {}), ...(f['trusted-actors'] ? { trustedActors: list(f['trusted-actors'])! } : {}) };
        const set = ingestText(io.read(pos[0] === '-' ? '/dev/stdin' : pos[0]), fmt, o, f.params ? io.read(f.params) : undefined);
        const out = f.out ?? 'autopilot.traces.json';
        io.write(out, JSON.stringify(set));
        const flagged = new Map<string, { n: number; why: string; what: string }>();
        for (const t of set.traces) if (t.sensitive.length) { const x = flagged.get(t.id) ?? { n: 0, why: t.sensitive.join(', '), what: `${t.verb} ${t.resource}` }; x.n++; flagged.set(t.id, x); }
        const denied = set.traces.filter((t) => t.outcome === 'deny').length;
        return { ok: true, text: [`${set.traces.length} action(s) read, ${set.rejected.length} rejected${set.truncated ? `, ${set.truncated} dropped over the cap` : ''}, ${denied} denied; wrote ${out}`, ...set.rejected.slice(0, 5).map((r) => `  rejected #${r.index}: ${r.reason}`), ...(flagged.size ? ['sensitive (need explicit confirmation, never included automatically):', ...[...flagged].map(([id, x]) => `  ${id}  ${x.what} x${x.n}  [${x.why}]`)] : [])].join('\n') };
      }
      case 'propose': {
        if (pos[0] === undefined) throw new Error('propose: expected a traces file');
        const p = propose(json<TraceSet>(io, pos[0]), synthOpts(f, io));
        const out = f.out ?? 'autopilot.proposal.json';
        io.write(out, JSON.stringify(p));
        return { ok: true, text: `${summarize(p)}\n\nwrote ${out}. Next: pca autopilot verify ${out} ${pos[0]}` };
      }
      case 'verify': {
        if (pos[0] === undefined || pos[1] === undefined) throw new Error('verify: expected <proposal.json> <traces.json>');
        const p = json<Proposal>(io, pos[0]);
        const rep = await verifyProposal(p, json<TraceSet>(io, pos[1]), f.existing ? { existing: json<unknown>(io, f.existing) } : {});
        const out = f.out ?? 'autopilot.report.json';
        io.write(out, JSON.stringify(rep));
        return { ok: rep.ok, text: `${summarize(p, rep)}\n\nwrote ${out}` };
      }
      case 'review': {
        if (pos[0] === undefined || pos[1] === undefined) throw new Error('review: expected <proposal.json> <report.json>');
        const p = json<Proposal>(io, pos[0]);
        const rep = json<Report>(io, pos[1]);
        const text = summarize(p, rep);
        if (f.yes === undefined) return { ok: rep.ok, text: `${text}\n\n(nothing signed: pass --yes with --reviewer-key to sign)` };
        const sk = secret(io, f['reviewer-key']);
        const at = num(f, 'now') ?? io.now();
        const a = signApproval(sk, p, rep, { at });
        const out = f.out ?? 'autopilot.approval.json';
        io.write(out, JSON.stringify(a));
        let tail = `signed by ${a.principal.slice(0, 12)}, valid ${Math.round((a.expires_at - a.at) / 60000)} min; wrote ${out}`;
        if (f.holder !== undefined) {
          if (!f.goal) throw new Error('--holder needs --goal');
          const g = issueGrant(p, rep, a, { principalSecret: sk, holder: f.holder, goal: f.goal, principals: [b64u(publicKeyOf(sk))], now: at });
          const gout = f['grant-out'] ?? 'autopilot.grant.json';
          io.write(gout, JSON.stringify(g.grant)); // exactly the encoded capability the proxy's http.grants loads
          io.write(`${gout}.goal-salt`, g.goalSalt);
          tail += `\ngrant minted for holder ${f.holder.slice(0, 12)}; wrote ${gout} (and ${gout}.goal-salt, which opens its goal commitment)`;
        }
        return { ok: true, text: `${text}\n\n${tail}` };
      }
      case 'amend': {
        if (pos[0] === undefined || pos[1] === undefined) throw new Error('amend: expected <proposal.json> <traces.json>');
        const base = json<Proposal>(io, pos[0]);
        const set = json<TraceSet>(io, pos[1]);
        const days = num(f, 'unused-days');
        const p = days !== undefined
          ? tighten(base, set, { unusedDays: days, now: num(f, 'now') ?? io.now(), ...(num(f, 'observed-from') !== undefined ? { observedFrom: num(f, 'observed-from')! } : {}) })
          : amend(base, set, { ...synthOpts(f, io), ...(num(f, 'min-repeats') !== undefined ? { minRepeats: num(f, 'min-repeats')! } : {}) });
        const out = f.out ?? 'autopilot.proposal.json';
        io.write(out, JSON.stringify(p));
        return { ok: true, text: `${summarize(p)}\n\nwrote ${out}. This is a new proposal: verify and review it again before it changes anything.` };
      }
      default:
        return { ok: false, text: `unknown autopilot command '${sub}'\n\n${AUTOPILOT_USAGE}` };
    }
  } catch (e) {
    return { ok: false, text: `autopilot ${sub}: ${e instanceof Error ? e.message : String(e)}` };
  }
}
