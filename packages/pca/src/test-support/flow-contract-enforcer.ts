/** The contract-enforcer flow ("never delete; review before deploy"), shared by the example and the tests. */
import { createMemoryDurableKv } from '../durable-state';
import { encodeKey, generateKeyPair } from '../keys';
import { ContractEnforcer } from '../contract-enforcer';
import { CONTRACT_VERSION, signContract } from '../contracts';

export async function runContractFlow(verbs: string[]): Promise<Array<{ verb: string; allow: boolean; reason: string }>> {
  const principal = generateKeyPair();
  const contract = signContract(
    {
      version: CONTRACT_VERSION,
      principal: encodeKey(principal.publicKey),
      clauses: [
        { id: 'no-delete', kind: 'never', p: { verb: 'delete' } },
        { id: 'review-first', kind: 'precedes', p: { verb: 'review' }, q: { verb: 'deploy' } },
      ],
    },
    principal.secretKey,
  );

  // Use `openDurableState({ dir })` instead of the memory kv for state that survives a restart.
  const enforcer = ContractEnforcer.open(createMemoryDurableKv(), contract, { principal: encodeKey(principal.publicKey) });

  // `permitted` is the verdict of your normal verifier (requirePCA / verifyPCActn): the contract can only ADD refusals.
  const out: Array<{ verb: string; allow: boolean; reason: string }> = [];
  for (const verb of verbs) {
    const r = await enforcer.check({ action: { verb, resource: '/service' } }, true);
    out.push({ verb, allow: r.allow, reason: r.reason });
  }
  return out;
}
