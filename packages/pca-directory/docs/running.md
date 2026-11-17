# Running a log, a witness and a monitor

Trust in a directory comes from independence: several logs run by different parties, several witnesses that are not the log operator, and monitors that anyone can run. Each is small.

## A log

```
npx pca-directory-log --id acme-log --key log.key --data ./log-data --port 8080 \
  --witness <witness key> --witness <witness key> --min-cosigs 2 [--issuer <issuer key> ...] [--max-per-hour 60]
```

- `--key` is created on first run (mode 0600). The public key is printed: publish it, relying parties pin it.
- `--data` holds the entries and the cosignatures as append-only files. Back it up; losing it forks your own log.
- Without `--issuer` the log is open: anyone with a valid signed passport and its subject key can be listed. Relying parties choose which issuers to trust, so an open log is useful. Add `--issuer` to restrict a private log.
- `--witness` lists the witness keys whose cosignatures the log accepts. With none, `POST /cosignatures` refuses everything.
- The server speaks plain HTTP on `HOST` (default 127.0.0.1). Put TLS and, if the log is not open, authentication in front of `POST /entries`. Reads are public by design.
- One process owns a data directory. To run several, give the log the Postgres store from your own code (`DirectoryStore`); the store's compare-and-set on the index is what keeps them from forking the log.

Routes: `GET /sth`, `/consistency?from&to`, `/entries?from&limit`, `/entries/:index`, `/proof?digest`, `/status?subject`; `POST /entries`, `POST /cosignatures`.

## A witness

```
npx pca-directory-witness --key witness.key --state witness-state.json \
  --log https://a.example/v1/pca/directory=<log A signing key> \
  --log https://b.example/v1/pca/directory=<log B signing key> --interval 60
```

The witness polls each log, builds the consistency proof from the last head it cosigned, cosigns, and posts the cosignature back to the log. Give the log operator the printed witness key; they list it as trusted.

The rules it enforces, which are the whole point of a witness:

1. It only follows logs whose signing key you listed.
2. It cosigns a head only if it verifies, and only if it extends the last head it cosigned (a consistency proof) or is identical to it.
3. It never goes backwards.
4. If a log signs two different roots at one size, the witness refuses both, keeps the evidence and halts that log until an operator clears it.

Keep `--state` on durable storage and never restore it from an old backup: a witness that forgets can be rolled back by the log. Add `--port 8787` to also serve `POST /add-checkpoint` (`{ sth, proof? }`) for logs that prefer to push, and `GET /info`. Use `--once` to run a single pass from cron.

Run witnesses on different infrastructure, under different organisations, from the log. A witness run by the log operator adds nothing.

## A monitor

```ts
import { Monitor, httpLogClient } from '@atlasauth/pca-directory';

const monitor = new Monitor({
  log: { id: 'acme-log', guardian: '<log signing key>' },
  client: httpLogClient('https://a.example/v1/pca/directory'),
  witnesses: { witnessKeys: ['<w1>', '<w2>', '<w3>'], threshold: 2 },
  maxHeadAgeMs: 3_600_000,
  watch: (e) => e.entry.mode === 'public' && myIssuers.includes(e.entry.issuer), // a passport appeared under your issuer
}, savedState);

const report = await monitor.poll();      // call it on a timer
save(monitor.state());                    // persist between runs
for (const a of report.alerts) page(a);   // bad_head, witness_shortfall, stale_head, rollback, equivocation, inconsistent, feed_mismatch, watch_hit
```

Each poll verifies the head, demands a consistency proof from the head it pinned, downloads the new entries and recomputes the tree: the entries must hash to the signed root. `monitor.gossip(head)` compares a head you learned elsewhere (another monitor, a witness, a stapled bundle) with the pinned one; two valid heads of one size with different roots return an `equivocation` alert carrying both, which anyone can verify against the log's key. Exchange heads with other monitors; one monitor can be shown a different log than the rest.

Watch for passports under your own issuer key that you did not issue: that is how a stolen issuer key shows up.

## Rotating a log's key

```
npx pca-directory-log --id acme-log --key log.key --data ./log-data --port 8080 \
  --witness <w1> --witness <w2> --witness <w3> --rotation-threshold 2 --rotate-to log-2.key
```

The log creates `log-2.key`, stops accepting submissions and publishes a pending transition at `GET /rotation`. Each running witness picks it up on its next pass: it cosigns the log's final head if it has not, then the transition, and posts the cosignature to `POST /rotation/cosignatures`. When `--rotation-threshold` witnesses have done so the log switches to the new key and says so; restart it with `--key log-2.key` from then on. If the witnesses cannot be reached the log stays on the old key and keeps waiting; stop it and start it without `--rotate-to` to abandon the rotation (a witness that already cosigned the transition then refuses heads larger than the handover until its operator runs `pca-directory-witness cancel-retirement --key witness.key --state witness-state.json --guardian <the old log key>`).

A witness that was down during the rotation cannot follow the new key by itself, and should not be pointed at it blindly. Give it the published transitions and the witness set you trust:

```
npx pca-directory-witness follow --key witness.key --state witness-state.json --from <the old log key> \
  --log https://a.example/v1/pca/directory=<the new log key> --transition https://a.example/v1/pca/directory/key-transitions \
  --witness <w1> --witness <w2> --witness <w3> --threshold 2
```

It checks that every transition is signed by both keys and cosigned by the threshold of those witnesses, that the chain starts at the key it follows, that it never cosigned the old key beyond the handover, and (fetching a consistency proof from the log) that its last cosigned head is part of the history that was handed over. Then it moves to the new key. Restart the witness with `--log <url>=<the new log key>`.

Tell relying parties nothing: they keep the key they pinned and follow the published transition. Publish the new key anyway, so new relying parties pin it directly.

## Freshness tokens

An agent that wants relying parties to be able to demand fresh proof offline refreshes its bundle on a timer:

```ts
bundle = await refreshBundle(bundle, [{ id: 'acme-log', client: httpLogClient(url) }, ...]);
```

One request per log, every few minutes. The log re-signs its current head on each request and attaches the witness cosignatures that still apply to it; if entries were appended since the witnesses last cosigned, the token fails the witness quorum until they have, so run witnesses on a short interval (`--interval 30`) if you want 10 minute tokens.
