pca_clock_v3p.spthy on cloud-box-5 (shared lease, nice 10), tamarin-prover 1.12.0, --prove, +RTS -N4 -M8g; each run well under a minute.
v3p.txt        : default model.   executable_accept/after_tick/stale_accept_exists verified; snapshot_expiry VERIFIED (59 steps);
                 no_accept_after_expiry_realtime FALSIFIED (stale snapshot trace; expected, not an implementation attack).
v3p_noexp.txt  : -DNO_EXPIRY_CHECK. snapshot_expiry FALSIFIED (so the !Le premise is what enforces it); realtime falsified.
Meaning: persistent snapshots prove only the snapshot-relative expiry (a table fact). The real-time no_accept_after_expiry
is NOT proved by this encoding and stays OPEN pending the linear-clock proof.
