# Changelog: @atlasauth/pca-mpc

## Unreleased

### Fixed

- **Identifiable abort no longer depends on message timing in the blame round.** A party whose MAC share was wrong runs the blame round too, finds every other party's data consistent and aborts accusing the dealer. Its abort frame used to poison an honest party's mesh on arrival, so an honest party still waiting for another honest party's blame data ended with a second-hand `peer-abort` (an unverified claim naming the dealer) instead of naming the cheater itself; with every honest party slower than the cheater, nobody named it first-hand. During the blame round an abort claim is now read in link order, behind the frames the peer sent before it (`Mesh.setDeferAborts`): honest parties always send their blame data before aborting, so each honest party completes its own check and names the cheater (`mac-check`, blamed = cheater) whatever the arrival order. An abort that arrives before a peer's blame data still ends the round at once. Tests: `src/net/identify.test.ts` (6b, forced order through a delaying proxy), `src/net/mutation-kill-r13-g6-mesh-defer.test.ts`. Test infrastructure: the delaying `FaultProxy` now delivers delayed bytes before passing on a close (it used to drop them). The in-memory test mesh (`MemMesh`) implements the same deferral.

## 0.4.0 - 2026-10-11

BREAKING: wire version 2 (both peers must upgrade).

### Security

- **R5-G1: `WIRE_VERSION` bumped 1 -> 2; version mismatch is a typed abort.** The R4-12 OT tweak change is incompatible on the wire but shipped without a version bump, so old and new peers passed hello and then diverged inside the OT layer (misattributed to a cheater). `WIRE_VERSION` is now 2, a peer sending any other integer `v` is refused at its first frame with `NetAbort` kind `version` (`peer N speaks wire version V ... upgrade both peers`), and the OT session bindings carry an explicit `/v2` label (`net-session/v2`, `ot-crh-tweak-domain/v2`) so a direct (non-mesh) misuse of old and new code also cannot share a tweak domain. Both peers must upgrade. Tests: `src/net/wire-version.test.ts`.
- **R4-12: OT-extension hash tweak made globally unique (wire change, defence in depth).** `tmmoCrh` used the row position within a call as the tweak and restarted at 0 every round (the comment referred to a nonexistent `firstIndex`). Analysis and a 209k-input instrumented run found no collision: the hashed rows are fresh PRG output, so the construction was safe (not exploitable). The tweak is now (64-bit session domain || 64-bit channel-global row index), so no two hash calls of a channel share a tweak and channels are separated. OT messages change; both peers must upgrade. Argument: `docs/pca/security/pca-mpc-spdz-soundness.md` section 8. Tests: `src/otx-tweak-collision.test.ts`, `src/otx.test.ts`.
- **RT-04: selective failure in the dealer-free (OT) triple generation leaked honest input bits (High).** The OT receiver
  chose with the plain bits of its additive share, so a corrupt OT sender could make the sacrifice / MAC-check abort exactly
  when a chosen share bit was 1, and the abort pattern (plus the public Beaver opening) gave the honest party's input bit
  (red-team PoC: 11 of 11 runs). Fixed with the MASCOT remedy (`src/enc.ts`): receivers now draw `61 + 3s` uniform choice bits
  (`s = 64` by default, so 253 OTs per multiplication instead of 61; `s < 40` is refused unless the test-only `unsafeStatSec` flag is set) and their share is the gadget sum `<g, b>` for a public gadget `g`.
  A selective-failure predicate that holds with probability at least 2^-s leaves the share within 2^-s of uniform (leftover
  hash lemma); a rarer predicate is observed with probability below 2^-s. This covers the triple shares, the sacrifice
  partners, and the MAC-key shares (`authenticate` had the same structure). In the networked dealer-free mode
  (`src/net/offline-net.ts`) the same encoding is used, and the pairwise-tag layer (whose receiver operands are derived
  values with no encoding of their own) splits each operand as `e + d` with a fresh encoded `e`.
  Regression: `src/selective-failure.test.ts` re-runs the PoC (200 runs per predicate): the attacker's recovery rate is
  chance, abort is uncorrelated with the share bit, and a positive control with the legacy encoding (`statSec: 0`) recovers
  the bit every time. Bound and caveats: `docs/pca/security/pca-mpc-spdz-soundness.md` section 7.
- The networked gadget is a commit-reveal value contributed by every party (rounds `gd-c`, `gd-o`).
- New option `NoDealerOptions.statSec` (default 64; `0` is the legacy, vulnerable encoding for tests only).

- **BREAKING (wire): KOS check strengthened (F-9).** Roy (CRYPTO 2022, ePrint 2022/192) shows the KOS consistency-check proof is incorrect and that attacks succeed with probability about 2^-s for `s` extra rows, so the stated 2^-128 held only for s = 64 as 2^-64. `SSEC` is now 128 (64 more padding rows in every extension round, so the `u` matrix, transcripts and any recorded vectors change, and peers on the old value will abort). The best known attack is then about 2^-128; this is argued from the attack analysis, not proved, and SoftSpokenOT's own check was not implemented (I could not read its exact parameters).

### Added

- Networked dealer-free attribution: after a failed sacrifice the parties disclose and audit the discarded triple's OT transcript
  (`src/net/forensics.ts`, round `forensic`), so a wrong operand in the offline triple products is NAMED (`blamed`), not only detected.
- `OfflineCheatingAbort` (subclass of `MacCheckAbort`): an offline abort in the in-process dealer-free phase now names the
  party whose OT transcript of the discarded triple is inconsistent (a sender whose chosen pair does not contain the value
  the receiver got, or a party whose product share does not follow from its OT transcripts) in `blamed`.

### Performance

- OT extension rewritten on typed arrays (`src/otx.ts`): AES-128-CTR column PRG (one cipher call per column per round), 32x32 bit-block transpose,
  GF(2^128) as four u32 words with Horner combination in the KOS check, batched fixed-key-AES TMMO correlation-robust hash (replaces
  per-row SHA-256; ideal-cipher model), boundary conversions via hex. Differential tests against naive references: `src/otx.test.ts`.
- All multiplications of one triple run in two batched OT-extension rounds instead of dozens of small ones.
- `bench/triples.ts` (per-triple cost). Steady state, in process, s = 64, one core: 2 parties 257-417 ms -> 12-13 ms, 3 parties
  593-637 ms -> 34 ms (the s = 40 post-fix numbers were 138 / 415 ms). Test suite 687 s -> 161 s.
- Not done: Mersenne-61 field arithmetic without BigInt and worker_threads parallelism; after the rewrite field arithmetic is about
  5% of the profile, so neither is worth the added surface.
- The PRG and CRH changed, so the OT stream differs from earlier builds (the wire format is already broken by SSEC = 128).

### Changed

- 253 instead of 61 OTs per multiplication; net effect after the performance work above is a large speed-up.
