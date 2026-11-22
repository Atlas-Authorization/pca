---
title: Operate a ledger witness
order: 11
---

# Operate a ledger witness

A transparency log proves nothing about itself. What makes it evidence is a **witness**: a separate party that cosigns a log's checkpoint only when it is genuine and consistent with the last checkpoint it cosigned. Once at least one witness you trust and that is independent of the log's operator holds the log's history, the operator cannot rewrite it, truncate it, or show you a different one without the witness refusing to cosign. See [the ledger guide](./transparency-ledger.md) for what the log itself guarantees.

This page is for the party running a witness. PCA ships a **reference witness**: a small HTTP service in a minimal container image. One witness can follow many logs.

## Who should run one

The value of a witness is its independence. A witness run by the log's operator, on the operator's machines, under the operator's keys protects nobody from the operator. Run yours when you are a customer, an auditor, a regulator, or any party with a stake in the log being honest; or recruit one. The reference witness is deliberately small enough to be audited and run by anyone.

## What it does

For every log it is configured for, the witness remembers one thing: the latest checkpoint it cosigned. On a cosign request it:

1. checks the checkpoint is signed by that log's **pinned guardian key**;
2. accepts the first checkpoint it ever sees for a log (trust on first use, so check the key and the first checkpoint out of band);
3. for a later checkpoint, requires an RFC 9162 **consistency proof** from the last cosigned one and checks it itself;
4. refuses a smaller size (`rollback`) and a different root at the same size (`equivocation`, and it stores both heads as evidence anyone can verify);
5. records the new checkpoint durably **before** it returns the cosignature.

The cosignature is bound to that exact log, size, root and previous root. It is useless anywhere else.

## Run it

Create the witness key. This prints only the **public** key. The secret stays in the file, mode `0600`.

```sh
docker run --rm -v "$PWD/witness:/etc/pca-witness" pca-witness init --key /etc/pca-witness/key
```

Describe the logs you witness in `witness/logs.json`:

```json
[{ "instance_id": "prod-1", "principal": "grant-1", "guardian_public": "<the guardian's public key, base64url>" }]
```

Start it, with a read-only root filesystem and the state on a volume:

```sh
docker run -d --name pca-witness --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 8080:8080 \
  -v "$PWD/witness:/etc/pca-witness:ro" -v pca-witness-state:/var/lib/witness \
  pca-witness
```

The image is distroless: no shell, no package manager, a non-root user, one JavaScript file. It listens on port 8080 (`--port`, `--host`).

| Mount | Holds | Notes |
|---|---|---|
| `/etc/pca-witness/key` | the witness secret key | must not be readable by others or writable by the group (`0600`, `0400` or `0440`); the process refuses to start otherwise |
| `/etc/pca-witness/logs.json` | the logs and their guardian keys | read-only |
| `/var/lib/witness` | the durable state | back it up; keep **one** container per volume on **one** host |

## The API

| Route | Does |
|---|---|
| `POST /v1/cosign` with `{ "sth": <checkpoint>, "proof": <consistency proof> }` | the cosignature and the head it covers, or a refusal |
| `GET /v1/key` | the witness's public key and the logs it follows |
| `GET /v1/state/<instance>/<principal>` | the last cosigned head, its cosignature, and any equivocation evidence |
| `GET /healthz` | liveness |

Refusals are exact: `400 malformed_request`, `403 bad_signature`, `404 unknown_log`, `409 proof_required`, `409 inconsistent`, `409 rollback`, `409 equivocation`, `500 state_unavailable`. A `500` never comes with a cosignature. Bodies are capped at 256 KiB.

The log's operator calls `cosign` after each checkpoint and attaches the returned cosignature to the checkpoint it publishes. Readers then ask for a witness threshold:

```ts
verifyTreeHead(checkpoint, guardianPublic, { witnessKeys: [theWitnessPublicKey], threshold: 1 });
```

Use several witnesses and a threshold above one when you can.

## Operating it

- **Monitor.** Poll `GET /v1/state/...` for each log. A non-empty `evidence` list means the guardian signed two roots for one size: proof of misbehaviour, checkable by anyone with the guardian's public key (`detectTreeHeadEquivocation`). Alert on any `409`.
- **Keys.** The witness key identifies you to every reader that pins it. Rotate by running a new witness under a new key alongside the old one, then retire the old key from readers' policies. A guardian key rotation needs a new `logs.json` entry and a fresh first sight.
- **Backups.** The state is a hash-chained journal. Restoring an **older** copy makes the witness forget what it cosigned, and nothing local detects it; treat a restore as a reset and re-establish trust with the logs it follows. Do not run two witnesses on one state directory.
- **Secrets.** Nothing but the public key and one status line per request is ever logged. Keep the key file out of images and shell history.
- **Availability.** If the witness is down, readers that require its cosignature fail closed. Run more than one.

## Failure modes

| What happens | Result |
|---|---|
| the key file is missing, the wrong size, or readable by others | the process exits with an error |
| a head for a log you did not configure | `404 unknown_log` |
| a head not signed by the pinned guardian | `403 bad_signature` |
| a head with no proof, or a proof that does not connect | `409`; nothing recorded |
| the log shrank, or forked at a size already cosigned | `409`; the first head stands; a fork is recorded as evidence |
| the state volume is unwritable or corrupt | `500 state_unavailable`; no cosignature |

## Limits

- Independence is yours to arrange. The reference witness protects against an operator only if the operator does not control it.
- First sight is trusted.
- It does not detect censorship: it sees only the checkpoints it is sent.
- One host per state volume; no clustering.
- No rate limiting or authentication on the endpoint: put it behind your own network controls. A request can never advance the witness without a genuine guardian-signed head and a proof, but unauthenticated callers can make it do work.
- Independent audit: not done.
