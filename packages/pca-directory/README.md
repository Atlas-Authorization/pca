# @atlasauth/pca-directory

> Maturity: **hardened** (hardened, awaiting independent witnesses and an independent audit). The log, witness and checker are finished and covered by adversarial tests; the trust model needs witnesses run by parties other than the log operator, and an outside review. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

A public agent trust directory: certificate transparency for agent identity.

A site that meets an unknown agent can ask one question before it trusts it: **is this passport in independent, append-only logs that witnesses have cosigned, and has it been revoked?** An agent that wants to be trusted shows a passport plus a stapled proof, the way a TLS server shows a certificate plus SCTs.

```
agent  ── passport + stapled proof ──▶  relying party  ── checkAgent() ──▶  trusted | untrusted | unknown
                                          │ (offline)
   log A ◀── submit ── issuer / agent     │ (optional, live)
   log B ◀── witnesses cosign heads       └──▶ logs: fresh head, consistency, revocations
   monitors follow every log, raise equivocation and rollback
```

It builds on `@atlasauth/pca`: agent passports, the transparency ledger (RFC 9162 trees, signed tree heads, inclusion and consistency proofs) and C2SP-style witness cosignatures. Nothing here changes the PCA wire format.

## What is in the box

| Piece | What it does |
| --- | --- |
| `DirectoryLog` | An append-only Merkle log of passport registrations, updates and revocations. Signed tree heads, witness cosignatures, inclusion and consistency proofs, flood limits. Pluggable store (memory, file, Postgres). |
| `checkAgent` | The relying-party check. Verifies the passport (signature, window, hardware attestation), proves it is in at least N independent logs, checks freshness and revocation, and returns a tri-state decision with reasons. Fails closed. |
| `stapleBundle` / `encodeBundle` | The stapling format: passport + inclusion proofs + signed heads + cosignatures in one object or one header value. |
| `Monitor` | Follows a log, demands consistency proofs, recomputes the tree from the feed, detects rollback and split views (with witness gossip), and watches for entries you care about. |
| `Witness` | An independent cosigner that signs only heads that extend the last one it signed, and halts on a log it caught signing two roots of one size. |
| `pca-directory-log`, `pca-directory-witness` | Runnable servers for a log and a witness. |
| Hosted routes | `/v1/pca/directory/*` on Atlas, and a read-only lookup page. |

## For a relying party: decide whether to trust an agent

```ts
import { checkAgent, httpLogClient } from '@atlasauth/pca-directory';

const logs = [
  { id: 'log-a', guardian: '<log A signing key>', client: httpLogClient('https://a.example/v1/pca/directory') },
  { id: 'log-b', guardian: '<log B signing key>', client: httpLogClient('https://b.example/v1/pca/directory') },
];

const result = await checkAgent(bundleOrPassportOrCard, {
  logs,
  witnesses: { keys: ['<witness 1>', '<witness 2>', '<witness 3>'], threshold: 2 },
  policy: { trustedIssuers: ['<issuer key>'], minLogs: 2 },
});

if (result.decision !== 'trusted') deny(result.reasons);
```

`decision` is tri-state:

- `trusted`: every check passed in at least `minLogs` independent logs.
- `untrusted`: positive evidence against the agent or whoever presented it (forged proof, revoked, superseded, a split view, a rollback, a bad signature).
- `unknown`: nothing provably wrong, but not provably right either (no proof, quorum short, stale head, a log down, too few witnesses).

Deny on both. The difference is for logging, retries and for telling a mistake from an attack. Anything unexpected, including a thrown error, is `unknown` at best; `checkAgent` never throws.

**Offline.** Leave off `client` (or set `policy.online: 'off'`) and the check uses only the stapled bundle. It is exact about what it proves: this passport was in these logs at a head that enough witnesses cosigned. The head's age (`policy.maxSthAgeMs`, default `DEFAULT_MAX_STH_AGE_MS`: 1 hour) is the bound on how long a revocation can go unnoticed: a head older than that is `unknown`. Raise it for low-risk actions, shorten it for high-risk ones, or require a freshness token (below) so the agent carries the freshness and you stay offline.

**Freshness tokens.** An agent can attach a recent head and a non-revocation proof to its bundle, and refresh it every few minutes with one request per log:

```ts
bundle = await refreshBundle(bundle, logs);            // agent side, cheap
await checkAgent(bundle, { ..., policy: { freshness: { maxAgeMs: 10 * 60_000, require: true } } }); // relying party, offline
```

The token is the log's current head (with its witness cosignatures) and every entry the log holds for the agent, each proved against that head. A token that shows a revocation or a newer passport convicts the agent; a witnessed token no older than `maxAgeMs` that still lists the passport counts as a live check. What it does not prove: the log can still omit a revocation from the entries it shows, so require `minLogs` of 2 or more, and the token is only as fresh as the log's clock.

**Online.** With a `client` on a log, the check also fetches the log's current head, demands a consistency proof from the stapled head (a rewritten history, a rollback or a split view fails here), and looks up the subject's entries for a revocation or a newer passport. One honest log that has seen a revocation is enough to refuse the agent. `policy.online: 'require'` counts a log only if it answered.

What you must pin out of band: the logs' signing keys, the witness keys and the issuers you trust. Never take them from the thing you are verifying.

## For an agent: present a passport

```ts
import { stapleBundle, encodeBundle, withDirectoryHeader, withDirectoryExtension } from '@atlasauth/pca-directory';

// collect an inclusion proof from each log that lists you
const bundle = await stapleBundle(signedPassport, logs.map((l) => ({ id: l.id, client: l.client })));

// 1. as a header next to a Web Bot Auth signature (covered by it)
import { signRequest } from '@atlasauth/pca-webbotauth';
const signed = signRequest(withDirectoryHeader({ method, url, key, keyid }, bundle));

// 2. as an optional A2A agent card extension (add it before you sign the card)
const card = withDirectoryExtension(agentCard, bundle);
```

Verifier side: `bundleFromHeaders(headers, verified.covered)` refuses a header the signature did not cover; `bundleFromCard(card)` reads the extension. Both feed straight into `checkAgent`. A header is limited to about 16 KiB; larger bundles belong in the agent card or at a URL.

## For a log operator

```ts
import { DirectoryLog, signPop, signRevocation } from '@atlasauth/pca-directory';

const log = new DirectoryLog({ id: 'my-log', secret: logSecretKey, witnessKeys: ['<witness>'], issuers: 'any' });

// an agent registers: the signed passport plus a proof it holds the subject key
await log.submit({ passport: signedPassport, pop: signPop(agentSecret, 'my-log', signedPassport) }, 'caller-id');
// the issuer (or the agent's own key) revokes
await log.submit({ revocation: signRevocation(issuerSecret, signedPassport, { iat: Date.now() }) }, 'caller-id');
```

The log refuses anything it cannot verify: an invalid or expired passport, a hardware claim without a hardware verifier, a subject key whose holder did not consent (the proof of possession is bound to this log), an issuer outside the allow-list, a revocation not signed by the passport's issuer or subject. It limits each submitter (`flood`), the entries per subject and the total size. A full log still accepts revocations.

Run one as a service:

```
npx pca-directory-log --id my-log --key log.key --data ./log-data --port 8080 --witness <witness key> --min-cosigs 2
```

See [docs/running.md](docs/running.md) for logs, witnesses and monitors, and [docs/privacy.md](docs/privacy.md) for the privacy modes.

## Rotating a log's key

A log changes its signing key by publishing a witnessed transition: the old key signs the new key, the new key signs back, and the trusted witnesses cosign the transition (in the same cosignature format they use for tree heads). `proposeRotation`, `rotationCosign` and `completeRotation` run it; the log accepts nothing while it waits, and it refuses to switch without the witness quorum, so a rotation cannot skip the witnesses. A witness cosigns a transition only for the exact head it last cosigned, then retires the old key.

A relying party that pinned the old key accepts a head from the new one only through a chain of valid, witnessed, consecutive transitions from the pinned key (carried in the bundle, held in `TrustedLog.transitions`, or fetched live). A head from a key that a transition retired, larger than the size it handed over, is refused. The monitor verifies continuity across the rotation: the chain must resolve, and each transition must hand over exactly the history the monitor has verified.

Standalone: `pca-directory-log ... --rotate-to new.key --rotation-threshold 2` proposes the rotation at start-up and finishes it when the witnesses (running `pca-directory-witness`) have cosigned. Hosted: `POST /v1/pca/directory/rotation`, then `.../complete`. The hosted log signs with its own per-instance key, kept apart from the guardian key the grant ledger uses, so rotating the directory never changes grant signing.

A witness that was down during a rotation adopts the new key without being reconfigured blind: `pca-directory-witness follow --from <old key> --log <url>=<new key> --transition <file or URL> --witness <key> ... --threshold N` verifies the witnessed transition chain and that what it had cosigned is part of the handed-over history. `pca-directory-witness cancel-retirement --guardian <key>` undoes the retirement of a key whose rotation the log abandoned.

## Privacy: public and hashed entries

An entry is `public` (the log serves the signed passport and the keys) or `hashed` (the log publishes only a domain-separated hash of the subject key and of the issuer key, and the digest of the passport; the passport itself is never served). A hashed agent presents the passport in its bundle; a relying party who knows the agent's key can compute the lookup reference. The trade-offs, including what the log operator still sees at submission time and why hashes are not secrecy, are written out in [docs/privacy.md](docs/privacy.md).

## Threat model, honestly

- A log can lie to one party. Witness cosignatures and monitors turn that into evidence: two validly signed heads of one size with different roots are a self-contained proof, and an honest witness never cosigns both.
- A log can withhold. A revocation the log hides from you is invisible offline; the head-age bound (or a freshness token) limits it, a live check against several logs removes it.
- Witnesses prove a head is the one they saw; they do not vouch for the time. Freshness comes from the log's signed timestamp, so a compromised log can keep re-signing an old tree. Monitors that see a larger consistent head catch that.
- The directory says a passport is listed, current and unrevoked. It does not say the agent is safe. Listing requires the issuer's signature, not the issuer's approval of behaviour.
- The checks never use a classifier: every input to `trusted` is a signature, a proof or a pinned key. The returned `score` is a ranking hint and never an input.

## Hosted on Atlas

Enable `auth_config.pca.directory` (`{ enabled: true, open?, issuers?, modes? }`) and list witness keys in `auth_config.pca.witnesses`. The routes are `GET /v1/pca/directory` (identity and key), `/sth`, `/consistency`, `/entries`, `/entries/:index`, `/proof`, `/status`, `POST /entries` (operator key, or anyone when `open`) and `POST /cosignatures` (witnesses). A read-only lookup page is available at your API origin with `#pca_directory` appended to the console URL; it verifies the inclusion proofs, the head's signature (Ed25519, hybrid and ML-DSA / SLH-DSA; a pure post-quantum log needs its pinned PQ key) and the witness cosignatures in the browser, and follows key rotations, against the keys the directory serves or a log key you paste.

A site can advertise its directory in `/.well-known/pca-configuration` with the optional `directory` member (`{ id, url, log_keys, witnesses?, modes?, open? }`). Absent, the document is unchanged. `trustedLogFromDiscovery(doc)` turns it into `checkAgent` inputs; discovery comes from the site itself, so pin keys out of band when you need an independent root.

## Status

Hardened, awaiting independent witnesses and an independent audit. The log, witness and checker are exercised by adversarial tests (equivocation, rollback, forged and malformed proofs, stale heads, revoked-but-stapled passports, flooding, witness-quorum shortfall). It has not had an independent audit.
