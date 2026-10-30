import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { authzenPdp, type AccessEvaluationRequest, type AccessEvaluationsRequest, type PdpDecisionContext } from './index';

// The published AuthZEN interoperability scenario ("Todo"): a PEP asks a PDP about five users (their opaque subject ids are the
// ones the scenario's identity provider issues) and actions on users and todos. The vectors are the scenario's own decision
// files for the 1.0 evaluation API and the boxcar (Access Evaluations) API, unchanged (see fixtures/LICENSE-authzen-interop).
// The scenario's role policy is expressed as PCA authority: each role resolves to an agent whose permissions are exactly what
// the role may do, and an editor additionally gets update/delete only on a todo it owns (the host's resolver compares the
// owner, the way a host maps its own data onto authority).

interface Vector {
  request: AccessEvaluationRequest;
  expected: boolean;
}
interface BoxcarVector {
  request: AccessEvaluationsRequest;
  expected: Array<{ decision: boolean }>;
}
const load = (n: string) =>
  JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', `interop-todo-decisions-1_0-${n}.json`), 'utf8')) as { evaluation: Vector[]; evaluations?: BoxcarVector[] };

const DIRECTORY: Record<string, { email: string; role: 'admin' | 'editor' | 'viewer' }> = {
  CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs: { email: 'rick@the-citadel.com', role: 'admin' },
  CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs: { email: 'beth@the-smiths.com', role: 'viewer' },
  CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs: { email: 'morty@the-citadel.com', role: 'editor' },
  CiRmZDI2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs: { email: 'summer@the-smiths.com', role: 'editor' },
  CiRmZDQ2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs: { email: 'jerry@the-smiths.com', role: 'viewer' },
};
const VERB: Record<string, string> = {
  can_read_user: 'todo.read_user',
  can_read_todos: 'todo.read',
  can_create_todo: 'todo.create',
  can_update_todo: 'todo.update',
  can_delete_todo: 'todo.delete',
};
const AUD = 'rs_todo';
const authority = (verbs: string[]) => agent({ principal: generateKeyPair(), goal: 'todo roles', permissions: { todo: verbs }, aud: AUD });
const AGENTS = {
  viewer: authority(['read_user', 'read']),
  editor: authority(['read_user', 'read', 'create']),
  editorOwner: authority(['read_user', 'read', 'create', 'update', 'delete']),
  admin: authority(['read_user', 'read', 'create', 'update', 'delete']),
};

const pdp = authzenPdp({
  audience: AUD,
  insecureSkipPlanRootCheck: true,
  requireProof: false,
  requireAuthorizer: false,
  resolve: (req): PdpDecisionContext | null => {
    const who = DIRECTORY[req.subject.id];
    if (who === undefined || VERB[req.action.name] === undefined) return null; // unknown subject or action: no authority, deny
    const owns = req.resource.properties?.['ownerID'] === who.email;
    const a = who.role === 'admin' ? AGENTS.admin : who.role === 'editor' ? (owns ? AGENTS.editorOwner : AGENTS.editor) : AGENTS.viewer;
    return {
      grant: a.grant,
      chain: a.chain,
      policy: a.policy,
      budget: a.budget,
      // the host declares each action's reversibility: a grant's reversibility_max caveat denies an action with no class (0.5)
      toAction: (r) => ({
        verb: VERB[r.action.name] as string,
        resource: `${r.resource.type}:${r.resource.id}`,
        reversibilityClass: r.action.name === 'can_delete_todo' ? 'irreversible' : 'reversible',
      }),
    };
  },
});

describe('AuthZEN interoperability scenario (Todo): published decisions', () => {
  for (const n of ['01', '02']) {
    const vectors = load(n);
    it(`1.0-${n}: the fixture is the published 40 evaluation requests`, () => {
      expect(vectors.evaluation.length).toBe(40);
      expect(vectors.evaluation.some((v) => v.expected)).toBe(true);
      expect(vectors.evaluation.some((v) => !v.expected)).toBe(true);
    });
    it(`1.0-${n}: every Access Evaluation request gets exactly the published decision`, async () => {
      const got: boolean[] = [];
      for (const v of vectors.evaluation) got.push((await pdp.evaluate(v.request)).decision);
      expect(got).toEqual(vectors.evaluation.map((v) => v.expected));
    });
  }

  it('1.0-02: every Access Evaluations (boxcar) request gets exactly the published decisions, in order', async () => {
    const boxcars = load('02').evaluations ?? [];
    expect(boxcars.length).toBe(3);
    for (const b of boxcars) {
      const r = await pdp.evaluations(b.request);
      expect(r.evaluations.map((e) => ({ decision: e.decision }))).toEqual(b.expected);
    }
  });

  it('an unknown subject and an unknown action are denied, never permitted', async () => {
    const rick = Object.keys(DIRECTORY)[0] as string;
    const base = { resource: { type: 'todo', id: 't1' } };
    expect((await pdp.evaluate({ ...base, subject: { type: 'user', id: 'nobody' }, action: { name: 'can_read_todos' } })).decision).toBe(false);
    expect((await pdp.evaluate({ ...base, subject: { type: 'user', id: rick }, action: { name: 'can_launch_missiles' } })).decision).toBe(false);
  });
});
