# PCA ProVerif models

Tool: ProVerif 2.05 (`results/versions.txt`). Models port `formal/tamarin/*.spthy`; results compared in `AGREEMENT.md`.

| File | Ports |
|---|---|
| `pca_actn.pv` | `pca_actn.spthy` (chains of depth 1..3, honest delegation bounded to depth 3, replay store as restriction) |
| `pca_actn_expiry.pv` | lemma `no_accept_after_expiry` (3 epochs via ProVerif phases) |
| `pca_threshold.pv` | `pca_threshold.spthy` |
| `pca_attest.pv` | `pca_attest.spthy` |
| `pca_frost_sign.pv`, `pca_frost_dkg.pv` | `pca_frost_sign.spthy`, `pca_frost_dkg.spthy` (rev 3; `set preciseActions = true`) |
| `pca_allowlist.pv` | stateless anchor part of `pca_allowlist_rollback.spthy` (phases; see AGREEMENT-v3.md) |
| `pca_scope_resource.pv` | `pca_scope_resource.spthy`, bounded |
| `cv/*.cv` | CryptoVerif 2.13 computational proofs (see `cv/run_cv.sh`, `cv/results/`) |

Variants are generated from marker lines by `gen.sh` (`./gen.sh pca_actn.pv NO_GREF_CHECK [query-name] > out.pv`).
Replay: ProVerif tables cannot express an atomic consume-once store (variants `TABLE_CHECK_INSERT`, `TABLE_INSERT_FIRST` record this);
the shipped model encodes the store as a ProVerif `restriction` over fresh execution ids, the analogue of Tamarin's `OnceNonce`/`OnceCounter`.

## Reproduce (cloud box)
```
source ~/pcaenv.sh            # ProVerif 2.05, CryptoVerif 2.13 (opam switch pv)
cd formal/proverif
./run_all.sh 4 1800           # all models x variants x queries -> results/*.txt, results/logs/
python3 agreement.py          # -> AGREEMENT.md
./run_all_v3.sh 4 1800        # rev-3 models -> results/v3/ (compare in AGREEMENT-v3.md)
cd cv && ./run_cv.sh          # CryptoVerif -> cv/results/
```
