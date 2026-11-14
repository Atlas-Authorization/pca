/**
 * Run an agent's tool with no ambient authority. The tool is a WebAssembly module whose only import is a table of handles. A
 * handle exists only for an operation a verifier already allowed, works once by default, can be narrowed but never widened, and
 * leaves a receipt every time it is used, refused or not.
 *
 * The tool here is a few bytes of hand-assembled WebAssembly (buildTool), so no toolchain is needed. No runtime claim is
 * configured, so the receipts record the runtime class "none": a class has to be backed by a signed claim from an attestor you pin.
 *
 * Run it:  npm run sandbox      (exits nonzero if any outcome is not the expected one)
 */
import {
  authorize, buildPCActn, encodeKey, generateKeyPair, memoryPcaStore, mintGrant, paramsDigest,
  type AuthorizeResult, type PcaOperation, type PlanNode,
} from '@atlasauth/pca';
import { USE_ERR, buildTool, createSandbox, verifyReceiptChain } from '@atlasauth/pca-sandbox';
import { expectOutcome, finish } from './check.js';

// ---- the verifier side: a grant for the "notes" resource, and one strict decision per operation ------------------------------

const AUD = 'notes-service';
const principal = generateKeyPair();
const holder = generateKeyPair();
const { grant } = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  holder: encodeKey(holder.publicKey),
  goal: 'read notes',
  envelope: {
    predicates: [{ verb: ['notes.read'], resource: 'notes', where: [] }],
    caveats: [],
    agent_binding: {},
    risk_policy: { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 },
  },
});
const store = memoryPcaStore();
let counter = 0;
async function decide(op: PcaOperation): Promise<AuthorizeResult> {
  const node: PlanNode = { id: 'n1', verb: op.verb, resource: op.resource, params_digest: paramsDigest(op.params), reversibility_class: 'reversible' };
  const pcactn = buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params: op.params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD });
  return authorize({
    operation: op,
    pcactn,
  }, {
    audience: AUD,
    resolveGrant: async (ref: string) => (ref === grant.id ? grant : null),
    budgetStore: store,
    hooks: { revocation: () => ({ enforced: true as const, ok: true as const }) },
    plan: 'single-step' as const,
    risk: () => ({ blastRadius: 0, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
    // provenance by default: notes.read only reads, so an agent-chosen note id needs no principal confirmation
    provenance: { actions: (o: PcaOperation) => (o.verb === 'notes.read' ? { effects: ['read'] } : undefined) },
  });
}

// ---- the sandbox: host code that does the work, and a tool that can only ask for it ----------------------------------------

const executed: unknown[] = [];
const sandbox = createSandbox({
  executors: {
    // host code: it gets the SIGNED params, never anything the tool supplied
    'notes.read': async (op) => {
      executed.push(op.params);
      return new TextEncoder().encode(`note ${String(op.params.id)}: buy milk`);
    },
  },
});

const readNote7: PcaOperation = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };
const readNote8: PcaOperation = { verb: 'notes.read', resource: 'notes', params: { id: 'n-8' } };
const allowed7 = await decide(readNote7);

// The tool calls handle 1 with a 64-byte window and returns the first byte it received.
const callHandle = (handle: number) => buildTool({ calls: [{ handle, ptr: 0, cap: 64 }], returns: 'byte0' });
// Without `returns`, the tool hands back the use result code itself (0 for a good use, a USE_ERR code otherwise).
const callForCode = (handle: number) => buildTool({ calls: [{ handle, ptr: 0, cap: 64 }] });

expectOutcome('the verifier allowed n-7', allowed7.allow, true);
const h1 = sandbox.table.mint(allowed7, readNote7);
expectOutcome('the tool uses its handle', await sandbox.runAsync(callHandle(h1)), { ok: true, value: 'n'.charCodeAt(0) });
expectOutcome('the host ran the executor on the signed params', executed, [{ id: 'n-7' }]);
expectOutcome('a second use finds the handle spent', await sandbox.runAsync(callForCode(h1)), { ok: true, value: USE_ERR.spent });
expectOutcome('a handle that was never minted', await sandbox.runAsync(callForCode(9)), { ok: true, value: USE_ERR.unknown_handle });

// A handle for other params cannot be minted from this decision.
let minted = 'minted';
try { sandbox.table.mint(allowed7, readNote8); } catch (e) { minted = String((e as Error).message).split(':')[0] ?? 'error'; }
expectOutcome('minting for n-8 from the n-7 decision', minted, 'not_authorized');

// Deriving a narrower handle, then revoking the parent revokes the child.
const allowed8 = await decide(readNote8);
const parent = sandbox.table.mint(allowed8, readNote8, { uses: 2 });
const child = sandbox.table.attenuate(parent, { uses: 1 });
let widened = 'widened';
try { sandbox.table.attenuate(parent, { uses: 5 }); } catch (e) { widened = (e as Error).message; }
expectOutcome('a child cannot hold more than the parent has', widened, 'attenuate_widens');
sandbox.table.revoke(parent);
expectOutcome('revoking the parent kills the child', await sandbox.runAsync(callForCode(child)), { ok: true, value: USE_ERR.spent });
expectOutcome('the executor did not run again', executed.length, 1);

// A tool that asks for anything beyond the handles is refused before it runs.
const greedy = buildTool({ calls: [], extraImports: [{ module: 'wasi:sockets/tcp', name: 'connect' }] });
expectOutcome('a tool that imports a socket', await sandbox.runAsync(greedy), { ok: false, reason: 'ambient_import:wasi:sockets/tcp.connect' });

// Every use, refused ones included, is a link in a hash chain.
expectOutcome('the receipts, in order', sandbox.log.entries.map((e) => `${e.kind}:${e.outcome}:${e.reason}`), [
  'handle_use:ok:used', 'handle_use:refused:spent', 'handle_use:refused:unknown_handle', 'handle_use:refused:spent',
]);
expectOutcome('the receipt chain verifies', verifyReceiptChain(sandbox.log.entries), { ok: true });
expectOutcome('the runtime class recorded', sandbox.log.entries[0]?.runtime_class, 'none');

finish();
