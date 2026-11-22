// Oracle: @atlasauth/pca-agentcard (signed A2A Agent Cards, AgentFacts attested by PCA, well-known hosting, registry entry).
// Deterministic: Ed25519 keys from seeds (EdDSA is deterministic, so signed output compares byte for byte), fixed clocks, date-only or
// UTC-offset ISO strings (the date parser of a native runtime is not specified past ISO 8601).
// JOSE library messages after the first colon are compared up to that colon (norm() below; the native replay applies the same rule).
// PORTING (fn(args) -> native entry point, comparison rule):
//   constants()                                 DEFAULT_ALG, AGENT_FACTS_CONTEXT, PCA_ATTESTOR_ID, WELL_KNOWN_AGENT_CARD_PATH, WELL_KNOWN_AGENT_FACTS_PATH
//   jcsBytes(v) / validateAgentCard1(card)      as in the A2A oracle
//   buildAgentCard(passport, opts)              same name
//   issueSignedAgentCard(card, jwk, opts?)      opts alg, passport, kid, profile, schema; the card with signatures, bytes exact
//   verifyAgentCard(card, opts)                 opts jwks, key, alg, schema; result by value after norm()
//   issueAgentFacts(passport, opts) / addAttestation(facts, opts)    opts.attestorKey is a JWK; bytes exact
//   verifyAgentFacts(facts, opts)               opts jwks, key, alg, now; result by value after norm()
//   agentCardHandler(card, path, reqPath) / agentFactsHandler(facts, path, reqPath)    the response of the handler for reqPath, null when it declines (path may be absent)
//   toRegistryEntry(card, facts)                same name
import { createPrivateKey } from 'node:crypto';
import { Oracle, refWrite, seed } from './lib.mjs';

const M: any = await import('../../../packages/pca-agentcard/src/index.ts');
const o = new Oracle('agentcard', 'tools/pca-audit/oracles/agentcard.mts', 'TS-reference oracle for signed Agent Cards, AgentFacts attestations, hosting handlers and registry entries.');

const T0 = Date.parse('2026-06-01T00:00:00Z');
const PK8 = Buffer.from('302e020100300506032b657004220420', 'hex');
function keyOf(label: string) {
  const ko = createPrivateKey({ key: Buffer.concat([PK8, Buffer.from(seed(label))]), format: 'der', type: 'pkcs8' });
  const priv: any = ko.export({ format: 'jwk' });
  const { d: _d, ...pub } = priv;
  return { priv, pub };
}
const K1 = keyOf('agentcard/key1');
const K2 = keyOf('agentcard/key2');
const withKid = (k: any, kid: string) => ({ ...k, kid });
const jwks = (...ks: any[]) => ({ keys: ks });
const norm = (r: any): any => {
  const fix = (s: any) => (typeof s === 'string' ? s.replace(/^(signature( \d+)? did not verify|could not resolve verification key): .*$/s, '$1') : s);
  if (r && typeof r === 'object') {
    const c: any = { ...r };
    if (typeof c.reason === 'string') c.reason = fix(c.reason);
    if (Array.isArray(c.attestations)) c.attestations = c.attestations.map((a: any) => (a && typeof a.reason === 'string' ? { ...a, reason: fix(a.reason) } : a));
    return c;
  }
  return r;
};

const PASS = { id: 'p1', model_id: 'm', created_at: 1 };
const REF = { id: 'p1', uri: 'https://p.example/p1' };
const CARD = {
  name: 'Pay Agent', description: 'pays things', version: '1.0.0',
  supportedInterfaces: [{ url: 'https://a.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
  capabilities: { streaming: true }, defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
  skills: [{ id: 's1', name: 'pay', description: 'pay', tags: ['t'] }],
};

// ---- constants, JCS and schema (shared with the A2A package) -----------------------------------------------------------------
await o.run('constants', 'all', () => ({ DEFAULT_ALG: M.DEFAULT_ALG, AGENT_FACTS_CONTEXT: M.AGENT_FACTS_CONTEXT, PCA_ATTESTOR_ID: M.PCA_ATTESTOR_ID, WELL_KNOWN_AGENT_CARD_PATH: M.WELL_KNOWN_AGENT_CARD_PATH, WELL_KNOWN_AGENT_FACTS_PATH: M.WELL_KNOWN_AGENT_FACTS_PATH }), []);
const jvals: any[] = [null, true, 1, -0, 1.5, 1e21, 'a "\\', { b: 1, a: [1, { z: null }] }, { '😀': 1, '': 2 }, [[[]]], { x: '\ud800' }];
for (const [i, v] of jvals.entries()) await o.run('jcsBytes', `v${i}`, M.jcsBytes, [v]);
for (const [i, c] of [CARD, {}, null, { ...CARD, skills: 'x' }, { ...CARD, supportedInterfaces: [] }, { ...CARD, capabilities: null }].entries()) await o.run('validateAgentCard1', `c${i}`, M.validateAgentCard1, [c]);

// ---- build ---------------------------------------------------------------------------------------------------------------------
const bopts: any[] = [{ name: 'A' }, { name: 'A', skills: [], url: 'https://a.example', description: 'd', version: '1' }, { name: 'A', passportUri: 'https://u' }, { name: 'A', pcaProofRef: { verificationEndpoint: 'https://v', proofRef: 'r', aud: 'rs' } },
  { name: 'A', url: 'https://a.example', passportUri: 'https://u', pcaProofRef: { verificationEndpoint: 'https://v' } }, { name: 'A', description: '', version: '' }];
for (const [pi, p] of [PASS, REF, { id: 'bare' }, { id: 'p', uri: undefined }].entries()) for (const [oi, op] of bopts.entries()) await o.run('buildAgentCard', `p${pi}o${oi}`, M.buildAgentCard, [p, op]);
await o.run('buildAgentCard', 'null', M.buildAgentCard, [null, bopts[0]]);

// ---- issue / verify cards ----------------------------------------------------------------------------------------------------------
const built = M.buildAgentCard(REF, { name: 'Pay Agent', url: 'https://a.example', pcaProofRef: { verificationEndpoint: 'https://v/verify', aud: 'rs-1' } });
const FULLCARD = { ...CARD, ...built, name: 'Pay Agent' };
const cards: any[] = [built, FULLCARD, { ...CARD }, { name: 'n' }, { ...built, signatures: [{ protected: 'a', signature: 'b' }] }, { ...CARD, pcaPassport: 'weird' }, { ...built, bad: '\ud800' }, { ...built, big: 1e21 }];
const iopts: any[] = [{}, { kid: 'k1' }, { profile: 'a2a-1.0', kid: 'k1' }, { profile: 'a2a-1.0' }, { profile: 'pca-detached', kid: 'k1', passport: { id: 'p9', uri: 'https://x' } }, { passport: { id: 'p9' } }, { passport: {} },
  { schema: 'a2a-1.0' }, { schema: 'a2a-1.0', profile: 'a2a-1.0', kid: 'k1' }, { alg: 'ES256' }, { alg: 'EdDSA', kid: '' }];
for (const [ci, c] of cards.entries()) for (const [oi, op] of iopts.entries()) {
  if (ci > 2 && oi % 3 !== 0) continue;
  await o.run('issueSignedAgentCard', `c${ci}o${oi}`, (card: any, k: any, x: any) => M.issueSignedAgentCard(card, k, x), [c, K1.priv, op]);
}
await o.run('issueSignedAgentCard', 'noopts', (card: any, k: any) => M.issueSignedAgentCard(card, k), [built, K1.priv]);
await o.run('issueSignedAgentCard', 'pubkey', (card: any, k: any) => M.issueSignedAgentCard(card, k), [built, K1.pub]);

const issued: Record<string, any> = {};
issued.det = await M.issueSignedAgentCard(built, K1.priv, { kid: 'k1' });
issued.std = await M.issueSignedAgentCard(FULLCARD, K1.priv, { profile: 'a2a-1.0', kid: 'k1' });
issued.plain = await M.issueSignedAgentCard(built, K1.priv, {});
issued.two = await M.issueSignedAgentCard(issued.plain, K2.priv, { kid: 'k2' });
const vopts: any[] = [{ key: K1.pub }, { key: K2.pub }, { jwks: jwks(withKid(K1.pub, 'k1')) }, { jwks: jwks(withKid(K1.pub, 'k1'), withKid(K2.pub, 'k2')) }, { jwks: jwks(K1.pub) }, { jwks: jwks(K1.pub, K2.pub) }, {},
  { key: K1.pub, schema: 'a2a-1.0' }, { jwks: { keys: 'x' } }, { jwks: {} }, { key: { kty: 'OKP', crv: 'Ed25519', x: 'AA' } }, { key: K1.priv }, { key: 'x' }, { key: { kty: 'oct', k: 'AAAA' } }];
const vcards: any[] = [issued.det, issued.std, issued.plain, issued.two, built, { ...issued.plain, name: 'tampered' }, { ...issued.plain, signatures: [] }, { ...issued.plain, signatures: [null] }, { ...issued.plain, signatures: [0] },
  { ...issued.plain, signatures: [{}] }, { ...issued.plain, signatures: [{ protected: 5, signature: 'x' }] }, { ...issued.plain, signatures: [issued.plain.signatures[0], { protected: 'A', signature: 'A' }] },
  { ...issued.plain, pcaProof: { verificationEndpoint: 'https://other' } }, { ...issued.plain, bad: '\ud800' }, null, 5, 'x', [], {}];
for (const [ci, c] of vcards.entries()) for (const [oi, op] of vopts.entries()) {
  if (ci > 4 && oi > 6) continue;
  await o.run('verifyAgentCard', `c${ci}o${oi}`, async (card: any, x: any) => norm(await M.verifyAgentCard(card, x)), [c, op]);
}

// ---- AgentFacts -----------------------------------------------------------------------------------------------------------------------
const fopts = (x: any = {}) => ({ attestorKey: K1.priv, attests: { kyc: 'passed', tier: 2 }, now: T0, ...x });
const fcases: any[] = [fopts(), fopts({ kid: 'k1' }), fopts({ selfAsserted: { name: 'A', kyc: 'self' } }), fopts({ attestorId: 'did:ex:att', agentId: 'did:ex:agent' }), fopts({ validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z' }),
  fopts({ context: ['x'] }), fopts({ alg: 'ES256' }), fopts({ attests: {} }), fopts({ now: 8.64e15 }), fopts({ now: 8.64e15 + 1 }), fopts({ attests: { b: 1, a: [1.5] } }), fopts({ attests: { bad: '\ud800' } }), fopts({ attestorKey: K1.pub })];
for (const [pi, p] of [PASS, { id: 'did:ex:agent' }].entries()) for (const [i, f] of fcases.entries()) await o.run('issueAgentFacts', `p${pi}f${i}`, (pp: any, x: any) => M.issueAgentFacts(pp, x), [p, f]);
const facts1 = await M.issueAgentFacts(PASS, fopts({ kid: 'k1', selfAsserted: { name: 'A', kyc: 'self' }, validUntil: '2027-01-01T00:00:00Z' }));
const facts2 = await M.addAttestation(facts1, { attestorKey: K2.priv, attests: { audit: 'ok' }, attestorId: 'did:ex:other', kid: 'k2', validFrom: '2026-02-01', now: T0 });
for (const [i, a] of [{ attestorKey: K2.priv, attests: { audit: 'ok' }, now: T0 }, { attestorKey: K2.priv, attests: { x: 1 }, attestorId: 'did:ex:o', kid: 'k2', validFrom: '2026-01-01T00:00:00Z', validUntil: '2026-06-01T00:00:00Z' }, { attestorKey: K2.pub, attests: {}, now: T0 }].entries())
  await o.run('addAttestation', `a${i}`, (f: any, x: any) => M.addAttestation(f, x), [facts1, a]);
await o.run('addAttestation', 'chain', (f: any, x: any) => M.addAttestation(f, x), [facts2, { attestorKey: K1.priv, attests: { z: 1 }, now: T0 }]);

const NOW_OK = Date.parse('2026-07-01T00:00:00Z');
const mut = (f: any, edit: (c: any) => void) => { const c = JSON.parse(JSON.stringify(f)); edit(c); return c; };
const fvs: any[] = [facts1, facts2, mut(facts1, (c) => { c.id = 'other'; }), mut(facts1, (c) => { c.attestations[0].subject = 'other'; }), mut(facts1, (c) => { c.attestations[0].attests.kyc = 'tampered'; }), mut(facts1, (c) => { c.selfAsserted = 5; }),
  mut(facts1, (c) => { c.attestations = []; }), mut(facts1, (c) => { c.attestations = 'x'; }), mut(facts1, (c) => { delete c.attestations; }), mut(facts1, (c) => { c.attestations = [null]; }), mut(facts1, (c) => { c.attestations = [5]; }),
  mut(facts1, (c) => { c.attestations[0].validFrom = 'garbage'; }), mut(facts1, (c) => { c.attestations[0].validFrom = '2026-01-01'; }), mut(facts1, (c) => { c.attestations[0].validUntil = 'garbage'; }), mut(facts1, (c) => { c.attestations[0].validUntil = '2026-06-15T00:00:00Z'; }),
  mut(facts1, (c) => { c.attestations[0].attests = [1]; }), mut(facts1, (c) => { c.attestations[0].issuer = 'did:forged'; }), mut(facts1, (c) => { delete c.attestations[0].validUntil; }), mut(facts1, (c) => { c.attestations[0].signature.signature = 'AAAA'; }),
  mut(facts1, (c) => { c.attestations[0].signature = { protected: 5, signature: 'x' }; }), mut(facts1, (c) => { c.attestations[0].signature = {}; })];
const fvo: any[] = [{ key: K1.pub, now: NOW_OK }, { key: K2.pub, now: NOW_OK }, { jwks: jwks(withKid(K1.pub, 'k1'), withKid(K2.pub, 'k2')), now: NOW_OK }, { now: NOW_OK }, { key: K1.pub, now: T0 - 1 },
  { key: K1.pub, now: Date.parse('2027-01-01T00:00:00Z') }, { key: K1.pub, now: Date.parse('2027-01-01T00:00:00.001Z') }, { key: K1.pub, now: T0 }, { jwks: { keys: 'x' }, now: NOW_OK }];
for (const [fi, f] of fvs.entries()) for (const [oi, op] of fvo.entries()) {
  if (fi > 2 && oi > 4) continue;
  await o.run('verifyAgentFacts', `f${fi}o${oi}`, async (ff: any, x: any) => norm(await M.verifyAgentFacts(ff, x)), [f, op]);
}
await o.run('verifyAgentFacts', 'nosigdoc', async (ff: any, x: any) => norm(await M.verifyAgentFacts(ff, x)), [mut(facts1, (c) => { delete c.attestations[0].signature; }), { key: K1.pub, now: NOW_OK }]);

// ---- hosting + registry ----------------------------------------------------------------------------------------------------------------
const hostCard = issued.det;
for (const [i, [path, req]] of ([[undefined, '/.well-known/agent-card.json'], [undefined, '/.well-known/agent-card.json/'], [undefined, '/.well-known/agent-card.json?x=1'], [undefined, '/other'], [undefined, '/'], ['/a', '/a'], ['/a/', '/a'], ['/a', '/a/'], ['/', '/'], ['/a?q', '/a'], ['', ''], [undefined, '']] as any[]).entries()) {
  await o.run('agentCardHandler', `h${i}`, (c: any, p: any, r: any) => M.agentCardHandler(c, p ?? undefined)(r) ?? null, [hostCard, path, req]);
  await o.run('agentFactsHandler', `h${i}`, (f: any, p: any, r: any) => M.agentFactsHandler(f, p ?? undefined)(r) ?? null, [facts2, path === undefined ? undefined : path, req === '/.well-known/agent-card.json' ? '/.well-known/agent-facts.json' : req]);
}
for (const [i, [c, f]] of ([[hostCard, facts2], [hostCard, facts1], [{ name: 'n' }, facts1], [{ ...hostCard, url: 'not a url' }, facts1], [{ ...hostCard, url: 'https://a.example/deep/path?x#y' }, facts2], [{ ...hostCard, url: 'http://HOST:8080/x' }, facts1],
  [{ ...hostCard, url: 5 }, facts1], [{ ...hostCard, url: 'mailto:a@b' }, facts1], [{ ...hostCard, url: 'https://h/' }, mut(facts1, (x) => { x.attestations = [null, { attests: 5 }, { attests: { selfX: 1 } }]; })], [hostCard, mut(facts1, (x) => { delete x.attestations; delete x.selfAsserted; })],
  [{ ...hostCard, skills: [{ id: 's' }], version: '2' }, facts1]] as any[]).entries()) await o.run('toRegistryEntry', `e${i}`, M.toRegistryEntry, [c, f]);

refWrite(o, 'agentcard');
