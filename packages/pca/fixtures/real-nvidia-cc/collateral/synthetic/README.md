SYNTHETIC (not NVIDIA): a throwaway 3-cert ECDSA P-384 chain (Synthetic Root -> Synthetic ICA -> Synthetic Device,
leaf serial 0x1001) and CRLs (ecdsa-with-SHA256, as NVIDIA's are) used only to exercise the revoked-serial and
staleness paths of `checkNvidiaChainRevocation`, which cannot be tested against real NVIDIA CAs (their keys are not
ours). `ica-clean.der` lists nothing; `ica-revoked.der` revokes the leaf. Public artifacts only; private keys were
discarded.
