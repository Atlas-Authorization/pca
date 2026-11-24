# Agreement with the catalog packs (16598 defs)

Two heuristic labelers compared; neither is a human reading each operation. The rules see only names, bindings and parameter names and types: the pack's declared traits, roles, tags and effects are removed first (a write becomes a neutral update). "rules reach the pack": of the traits the pack carries, the share the rules also show. "pack confirms the rules": of the traits the rules show, the share the pack carries.

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 1137 | 1510 | 1136 | 99.9% | 75.2% | 84.6% |
| destructive | 2892 | 2654 | 2514 | 86.9% | 94.7% | 88.8% |
| external_communication | 167 | 1425 | 161 | 96.4% | 11.3% | 18.8% |
| privilege_change | 2401 | 2085 | 1914 | 79.7% | 91.8% | 83.1% |
| code_execution | 1390 | 1603 | 1320 | 95.0% | 82.3% | 87.0% |
| public_exposure | 89 | 2174 | 59 | 66.3% | 2.7% | 4.2% |
| financial_data_read | 1474 | 1623 | 1405 | 95.3% | 86.6% | 89.8% |
| scheduled | 393 | 1468 | 138 | 35.1% | 9.4% | 11.5% |
| bulk | 4200 | 4747 | 4200 | 100.0% | 88.5% | 91.6% |
| pii_access | 334 | 617 | 239 | 71.6% | 38.7% | 48.9% |
| credential_access | 2969 | 2725 | 2705 | 91.1% | 99.3% | 94.0% |
| data_export | 217 | 426 | 207 | 95.4% | 48.6% | 63.8% |

## aws-core

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 58 | 72 | 58 | 100.0% | 80.6% | 88.9% |
| destructive | 349 | 341 | 324 | 92.8% | 95.0% | 92.7% |
| external_communication | 13 | 144 | 13 | 100.0% | 9.0% | 15.6% |
| privilege_change | 355 | 332 | 320 | 90.1% | 96.4% | 91.8% |
| code_execution | 120 | 138 | 120 | 100.0% | 87.0% | 92.6% |
| public_exposure | 9 | 156 | 3 | 33.3% | 1.9% | 2.8% |
| financial_data_read | 57 | 50 | 44 | 77.2% | 88.0% | 81.8% |
| scheduled | 35 | 55 | 12 | 34.3% | 21.8% | 25.1% |
| bulk | 1218 | 1219 | 1218 | 100.0% | 99.9% | 99.9% |
| pii_access | 10 | 63 | 9 | 90.0% | 14.3% | 24.0% |
| credential_access | 658 | 650 | 646 | 98.2% | 99.4% | 98.2% |
| data_export | 22 | 78 | 21 | 95.5% | 26.9% | 41.0% |

## azure-core

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 601 | 715 | 601 | 100.0% | 84.1% | 85.5% |
| destructive | 229 | 212 | 209 | 91.3% | 98.6% | 94.0% |
| external_communication | 0 | 21 | 0 | - | 0.0% | 0.0% |
| privilege_change | 128 | 92 | 76 | 59.4% | 82.6% | 66.9% |
| code_execution | 201 | 198 | 175 | 87.1% | 88.4% | 86.0% |
| public_exposure | 0 | 277 | 0 | - | 0.0% | 0.0% |
| financial_data_read | 765 | 875 | 765 | 100.0% | 87.4% | 86.5% |
| scheduled | 13 | 713 | 13 | 100.0% | 1.8% | 2.0% |
| bulk | 204 | 249 | 204 | 100.0% | 81.9% | 88.5% |
| pii_access | 3 | 21 | 2 | 66.7% | 9.5% | 16.4% |
| credential_access | 318 | 164 | 164 | 51.6% | 100.0% | 63.1% |
| data_export | 25 | 52 | 25 | 100.0% | 48.1% | 64.2% |

## core

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 2 | 3 | 2 | 100.0% | 66.7% | 79.6% |
| destructive | 27 | 21 | 21 | 77.8% | 100.0% | 84.8% |
| external_communication | 0 | 12 | 0 | - | 0.0% | 0.0% |
| privilege_change | 8 | 4 | 4 | 50.0% | 100.0% | 65.3% |
| code_execution | 30 | 29 | 27 | 90.0% | 93.1% | 89.1% |
| public_exposure | 7 | 11 | 5 | 71.4% | 45.5% | 52.5% |
| scheduled | 6 | 6 | 2 | 33.3% | 33.3% | 30.2% |
| bulk | 115 | 115 | 115 | 100.0% | 100.0% | 100.0% |
| pii_access | 2 | 0 | 0 | 0.0% | - | 0.0% |
| credential_access | 9 | 7 | 7 | 77.8% | 100.0% | 86.7% |
| data_export | 0 | 4 | 0 | - | 0.0% | 0.0% |

## db

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 2 | 3 | 2 | 100.0% | 66.7% | 79.7% |
| destructive | 56 | 45 | 42 | 75.0% | 93.3% | 76.2% |
| external_communication | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |
| privilege_change | 24 | 18 | 17 | 70.8% | 94.4% | 78.3% |
| code_execution | 15 | 13 | 12 | 80.0% | 92.3% | 84.4% |
| public_exposure | 0 | 5 | 0 | - | 0.0% | 0.0% |
| financial_data_read | 2 | 3 | 2 | 100.0% | 66.7% | 79.7% |
| scheduled | 3 | 4 | 2 | 66.7% | 50.0% | 56.3% |
| bulk | 57 | 62 | 57 | 100.0% | 91.9% | 93.6% |
| credential_access | 34 | 19 | 19 | 55.9% | 100.0% | 67.0% |
| data_export | 10 | 10 | 8 | 80.0% | 80.0% | 78.8% |

## gcp-core

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 94 | 114 | 94 | 100.0% | 82.5% | 90.0% |
| destructive | 421 | 422 | 399 | 94.8% | 94.5% | 93.7% |
| external_communication | 0 | 67 | 0 | - | 0.0% | 0.0% |
| privilege_change | 418 | 390 | 369 | 88.3% | 94.6% | 89.9% |
| code_execution | 246 | 272 | 243 | 98.8% | 89.3% | 93.2% |
| public_exposure | 11 | 131 | 8 | 72.7% | 6.1% | 10.6% |
| financial_data_read | 79 | 92 | 79 | 100.0% | 85.9% | 92.2% |
| scheduled | 27 | 209 | 10 | 37.0% | 4.8% | 6.9% |
| bulk | 65 | 257 | 65 | 100.0% | 25.3% | 38.1% |
| pii_access | 20 | 24 | 20 | 100.0% | 83.3% | 90.8% |
| credential_access | 728 | 720 | 717 | 98.5% | 99.6% | 98.7% |
| data_export | 81 | 150 | 80 | 98.8% | 53.3% | 68.1% |

## github

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 38 | 85 | 38 | 100.0% | 44.7% | 60.1% |
| destructive | 202 | 207 | 199 | 98.5% | 96.1% | 96.8% |
| external_communication | 1 | 137 | 0 | 0.0% | 0.0% | -0.2% |
| privilege_change | 195 | 163 | 154 | 79.0% | 94.5% | 83.7% |
| code_execution | 151 | 170 | 151 | 100.0% | 88.8% | 93.2% |
| public_exposure | 28 | 372 | 23 | 82.1% | 6.2% | 7.6% |
| financial_data_read | 46 | 53 | 46 | 100.0% | 86.8% | 92.6% |
| scheduled | 2 | 45 | 0 | 0.0% | 0.0% | -0.3% |
| bulk | 73 | 90 | 73 | 100.0% | 81.1% | 88.8% |
| pii_access | 12 | 15 | 8 | 66.7% | 53.3% | 58.8% |
| credential_access | 152 | 153 | 152 | 100.0% | 99.3% | 99.6% |
| data_export | 15 | 15 | 12 | 80.0% | 80.0% | 79.8% |

## gitlab

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 13 | 35 | 13 | 100.0% | 37.1% | 53.4% |
| destructive | 146 | 137 | 133 | 91.1% | 97.1% | 93.2% |
| external_communication | 2 | 124 | 0 | 0.0% | 0.0% | -0.3% |
| privilege_change | 114 | 126 | 102 | 89.5% | 81.0% | 83.3% |
| code_execution | 102 | 128 | 102 | 100.0% | 79.7% | 87.5% |
| public_exposure | 2 | 322 | 2 | 100.0% | 0.6% | 0.9% |
| financial_data_read | 7 | 9 | 7 | 100.0% | 77.8% | 87.4% |
| scheduled | 4 | 70 | 4 | 100.0% | 5.7% | 10.2% |
| bulk | 137 | 301 | 137 | 100.0% | 45.5% | 55.2% |
| pii_access | 6 | 9 | 4 | 66.7% | 44.4% | 53.0% |
| credential_access | 225 | 223 | 222 | 98.7% | 99.6% | 98.9% |
| data_export | 42 | 77 | 42 | 100.0% | 54.5% | 69.1% |

## google-workspace

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 4 | 7 | 4 | 100.0% | 57.1% | 72.5% |
| destructive | 124 | 119 | 115 | 92.7% | 96.6% | 93.5% |
| external_communication | 15 | 117 | 15 | 100.0% | 12.8% | 19.6% |
| privilege_change | 148 | 159 | 133 | 89.9% | 83.6% | 82.9% |
| code_execution | 22 | 31 | 22 | 100.0% | 71.0% | 82.4% |
| public_exposure | 2 | 70 | 0 | 0.0% | 0.0% | -0.6% |
| financial_data_read | 13 | 17 | 13 | 100.0% | 76.5% | 86.4% |
| scheduled | 10 | 22 | 10 | 100.0% | 45.5% | 61.7% |
| bulk | 102 | 130 | 102 | 100.0% | 78.5% | 85.5% |
| pii_access | 35 | 98 | 35 | 100.0% | 35.7% | 48.8% |
| credential_access | 153 | 152 | 149 | 97.4% | 98.0% | 97.1% |
| data_export | 5 | 11 | 5 | 100.0% | 45.5% | 62.1% |

## hubspot

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 3 | 4 | 3 | 100.0% | 75.0% | 85.4% |
| destructive | 25 | 25 | 23 | 92.0% | 92.0% | 90.2% |
| external_communication | 8 | 27 | 8 | 100.0% | 29.6% | 40.4% |
| privilege_change | 9 | 8 | 8 | 88.9% | 100.0% | 93.7% |
| code_execution | 9 | 14 | 9 | 100.0% | 64.3% | 76.4% |
| public_exposure | 2 | 11 | 2 | 100.0% | 18.2% | 29.0% |
| financial_data_read | 6 | 0 | 0 | 0.0% | - | 0.0% |
| scheduled | 1 | 3 | 1 | 100.0% | 33.3% | 49.5% |
| bulk | 63 | 63 | 63 | 100.0% | 100.0% | 100.0% |
| pii_access | 14 | 14 | 10 | 71.4% | 71.4% | 68.2% |
| credential_access | 2 | 2 | 2 | 100.0% | 100.0% | 100.0% |
| data_export | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |

## identity

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 9 | 11 | 9 | 100.0% | 81.8% | 89.4% |
| destructive | 34 | 38 | 25 | 73.5% | 65.8% | 61.6% |
| external_communication | 4 | 10 | 4 | 100.0% | 40.0% | 55.7% |
| privilege_change | 131 | 79 | 79 | 60.3% | 100.0% | 43.7% |
| code_execution | 5 | 2 | 1 | 20.0% | 50.0% | 27.4% |
| public_exposure | 0 | 4 | 0 | - | 0.0% | 0.0% |
| scheduled | 0 | 2 | 0 | - | 0.0% | 0.0% |
| bulk | 42 | 42 | 42 | 100.0% | 100.0% | 100.0% |
| pii_access | 28 | 9 | 9 | 32.1% | 100.0% | 44.3% |
| credential_access | 35 | 21 | 21 | 60.0% | 100.0% | 70.6% |
| data_export | 4 | 4 | 4 | 100.0% | 100.0% | 100.0% |

## jira

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 3 | 16 | 3 | 100.0% | 18.8% | 28.0% |
| destructive | 16 | 19 | 16 | 100.0% | 84.2% | 89.7% |
| external_communication | 1 | 20 | 1 | 100.0% | 5.0% | 7.8% |
| privilege_change | 11 | 8 | 7 | 63.6% | 87.5% | 71.1% |
| code_execution | 4 | 6 | 4 | 100.0% | 66.7% | 79.0% |
| public_exposure | 1 | 23 | 1 | 100.0% | 4.3% | 6.6% |
| scheduled | 0 | 5 | 0 | - | 0.0% | 0.0% |
| bulk | 42 | 42 | 42 | 100.0% | 100.0% | 100.0% |
| pii_access | 5 | 2 | 2 | 40.0% | 100.0% | 55.9% |
| credential_access | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |
| data_export | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |

## k8s

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| destructive | 134 | 133 | 133 | 99.3% | 100.0% | 99.5% |
| privilege_change | 78 | 67 | 64 | 82.1% | 95.5% | 86.9% |
| code_execution | 125 | 103 | 98 | 78.4% | 95.1% | 83.1% |
| public_exposure | 0 | 83 | 0 | - | 0.0% | 0.0% |
| financial_data_read | 12 | 14 | 12 | 100.0% | 85.7% | 92.2% |
| scheduled | 5 | 40 | 5 | 100.0% | 12.5% | 21.2% |
| bulk | 174 | 174 | 174 | 100.0% | 100.0% | 100.0% |
| credential_access | 44 | 42 | 42 | 95.5% | 100.0% | 97.5% |

## linear

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 16 | 75 | 16 | 100.0% | 21.3% | 32.0% |
| destructive | 86 | 98 | 70 | 81.4% | 71.4% | 71.5% |
| external_communication | 12 | 157 | 12 | 100.0% | 7.6% | 10.7% |
| privilege_change | 61 | 49 | 37 | 60.7% | 75.5% | 63.8% |
| code_execution | 23 | 53 | 23 | 100.0% | 43.4% | 58.2% |
| public_exposure | 7 | 130 | 4 | 57.1% | 3.1% | 3.6% |
| financial_data_read | 5 | 6 | 5 | 100.0% | 83.3% | 90.8% |
| scheduled | 10 | 45 | 9 | 90.0% | 20.0% | 30.7% |
| bulk | 568 | 568 | 568 | 100.0% | 100.0% | 100.0% |
| pii_access | 19 | 24 | 19 | 100.0% | 79.2% | 87.9% |
| credential_access | 46 | 46 | 41 | 89.1% | 89.1% | 88.2% |
| data_export | 0 | 4 | 0 | - | 0.0% | 0.0% |

## m365

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 28 | 38 | 28 | 100.0% | 73.7% | 84.6% |
| destructive | 219 | 225 | 215 | 98.2% | 95.6% | 96.4% |
| external_communication | 40 | 152 | 40 | 100.0% | 26.3% | 39.4% |
| privilege_change | 224 | 185 | 173 | 77.2% | 93.5% | 82.5% |
| code_execution | 181 | 242 | 181 | 100.0% | 74.8% | 83.6% |
| public_exposure | 2 | 147 | 1 | 50.0% | 0.7% | 1.1% |
| financial_data_read | 18 | 21 | 18 | 100.0% | 85.7% | 92.2% |
| scheduled | 35 | 92 | 35 | 100.0% | 38.0% | 53.8% |
| bulk | 127 | 130 | 127 | 100.0% | 97.7% | 98.7% |
| pii_access | 14 | 93 | 11 | 78.6% | 11.8% | 19.4% |
| credential_access | 77 | 55 | 55 | 71.4% | 100.0% | 82.7% |
| data_export | 1 | 2 | 1 | 100.0% | 50.0% | 66.6% |

## notion

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| destructive | 4 | 5 | 4 | 100.0% | 80.0% | 87.0% |
| external_communication | 2 | 12 | 2 | 100.0% | 16.7% | 19.7% |
| privilege_change | 6 | 6 | 5 | 83.3% | 83.3% | 79.3% |
| public_exposure | 1 | 10 | 1 | 100.0% | 10.0% | 13.1% |
| bulk | 9 | 9 | 9 | 100.0% | 100.0% | 100.0% |
| pii_access | 4 | 2 | 2 | 50.0% | 100.0% | 63.5% |
| credential_access | 2 | 2 | 2 | 100.0% | 100.0% | 100.0% |
| data_export | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |

## payments-rails

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 62 | 67 | 62 | 100.0% | 92.5% | 87.1% |
| destructive | 21 | 20 | 20 | 95.2% | 100.0% | 96.9% |
| external_communication | 16 | 19 | 16 | 100.0% | 84.2% | 89.4% |
| privilege_change | 8 | 1 | 0 | 0.0% | 0.0% | -2.0% |
| code_execution | 1 | 2 | 1 | 100.0% | 50.0% | 66.2% |
| financial_data_read | 48 | 51 | 48 | 100.0% | 94.1% | 93.4% |
| scheduled | 5 | 5 | 3 | 60.0% | 60.0% | 57.7% |
| bulk | 52 | 52 | 52 | 100.0% | 100.0% | 100.0% |
| pii_access | 8 | 0 | 0 | 0.0% | - | 0.0% |
| credential_access | 3 | 2 | 2 | 66.7% | 100.0% | 79.5% |

## salesforce

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 2 | 3 | 2 | 100.0% | 66.7% | 79.6% |
| destructive | 22 | 17 | 14 | 63.6% | 82.4% | 66.0% |
| external_communication | 4 | 11 | 4 | 100.0% | 36.4% | 50.8% |
| privilege_change | 14 | 11 | 10 | 71.4% | 90.9% | 77.5% |
| code_execution | 12 | 14 | 12 | 100.0% | 85.7% | 91.3% |
| public_exposure | 1 | 3 | 1 | 100.0% | 33.3% | 49.3% |
| financial_data_read | 7 | 5 | 4 | 57.1% | 80.0% | 64.8% |
| scheduled | 0 | 3 | 0 | - | 0.0% | 0.0% |
| bulk | 55 | 57 | 55 | 100.0% | 96.5% | 96.4% |
| pii_access | 18 | 13 | 11 | 61.1% | 84.6% | 66.4% |
| credential_access | 4 | 3 | 3 | 75.0% | 100.0% | 85.3% |
| data_export | 2 | 1 | 1 | 50.0% | 100.0% | 66.3% |

## sendgrid

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 7 | 8 | 7 | 100.0% | 87.5% | 93.2% |
| destructive | 62 | 64 | 60 | 96.8% | 93.8% | 94.2% |
| external_communication | 8 | 70 | 8 | 100.0% | 11.4% | 17.3% |
| privilege_change | 36 | 31 | 27 | 75.0% | 87.1% | 78.7% |
| code_execution | 2 | 2 | 2 | 100.0% | 100.0% | 100.0% |
| public_exposure | 2 | 16 | 0 | 0.0% | 0.0% | -1.0% |
| financial_data_read | 10 | 12 | 10 | 100.0% | 83.3% | 90.6% |
| scheduled | 7 | 17 | 7 | 100.0% | 41.2% | 57.2% |
| bulk | 184 | 195 | 184 | 100.0% | 94.4% | 94.0% |
| pii_access | 23 | 67 | 22 | 95.7% | 32.8% | 43.6% |
| credential_access | 27 | 28 | 27 | 100.0% | 96.4% | 98.0% |
| data_export | 3 | 10 | 3 | 100.0% | 30.0% | 45.5% |

## shopify

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 15 | 19 | 15 | 100.0% | 78.9% | 86.2% |
| destructive | 19 | 17 | 17 | 89.5% | 100.0% | 93.4% |
| external_communication | 6 | 11 | 5 | 83.3% | 45.5% | 55.9% |
| privilege_change | 6 | 7 | 6 | 100.0% | 85.7% | 91.9% |
| code_execution | 5 | 5 | 4 | 80.0% | 80.0% | 79.1% |
| public_exposure | 4 | 13 | 3 | 75.0% | 23.1% | 31.7% |
| financial_data_read | 14 | 12 | 11 | 78.6% | 91.7% | 82.7% |
| scheduled | 0 | 7 | 0 | - | 0.0% | 0.0% |
| bulk | 48 | 49 | 48 | 100.0% | 98.0% | 98.2% |
| pii_access | 25 | 10 | 10 | 40.0% | 100.0% | 51.1% |
| credential_access | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |
| data_export | 2 | 1 | 1 | 50.0% | 100.0% | 66.3% |

## slack

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| destructive | 23 | 21 | 18 | 78.3% | 85.7% | 79.2% |
| external_communication | 7 | 45 | 6 | 85.7% | 13.3% | 17.3% |
| privilege_change | 46 | 47 | 43 | 93.5% | 91.5% | 89.7% |
| code_execution | 3 | 7 | 3 | 100.0% | 42.9% | 59.0% |
| public_exposure | 2 | 12 | 1 | 50.0% | 8.3% | 12.6% |
| scheduled | 5 | 7 | 3 | 60.0% | 42.9% | 48.3% |
| bulk | 174 | 174 | 174 | 100.0% | 100.0% | 100.0% |
| pii_access | 2 | 5 | 2 | 100.0% | 40.0% | 56.4% |
| credential_access | 4 | 4 | 4 | 100.0% | 100.0% | 100.0% |

## stripe

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 118 | 151 | 117 | 99.2% | 77.5% | 82.5% |
| destructive | 49 | 54 | 48 | 98.0% | 88.9% | 92.5% |
| external_communication | 4 | 44 | 4 | 100.0% | 9.1% | 15.5% |
| privilege_change | 43 | 27 | 21 | 48.8% | 77.8% | 57.3% |
| code_execution | 4 | 5 | 4 | 100.0% | 80.0% | 88.8% |
| public_exposure | 1 | 235 | 1 | 100.0% | 0.4% | 0.5% |
| financial_data_read | 220 | 218 | 182 | 82.7% | 83.5% | 70.7% |
| scheduled | 5 | 29 | 2 | 40.0% | 6.9% | 10.3% |
| bulk | 196 | 208 | 196 | 100.0% | 94.2% | 95.1% |
| pii_access | 31 | 36 | 26 | 83.9% | 72.2% | 76.1% |
| credential_access | 33 | 27 | 27 | 81.8% | 100.0% | 89.4% |
| data_export | 0 | 1 | 0 | - | 0.0% | 0.0% |

## terraform

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 10 | 15 | 10 | 100.0% | 66.7% | 79.6% |
| destructive | 426 | 213 | 213 | 50.0% | 100.0% | 41.1% |
| external_communication | 0 | 15 | 0 | - | 0.0% | 0.0% |
| privilege_change | 197 | 153 | 149 | 75.6% | 97.4% | 79.8% |
| code_execution | 77 | 79 | 74 | 96.1% | 93.7% | 94.2% |
| public_exposure | 0 | 46 | 0 | - | 0.0% | 0.0% |
| scheduled | 215 | 54 | 19 | 8.8% | 35.2% | 1.1% |
| bulk | 211 | 212 | 211 | 100.0% | 99.5% | 99.7% |
| pii_access | 0 | 3 | 0 | - | 0.0% | 0.0% |
| credential_access | 65 | 54 | 54 | 83.1% | 100.0% | 89.8% |
| data_export | 1 | 0 | 0 | 0.0% | - | 0.0% |

## travel

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 19 | 23 | 19 | 100.0% | 82.6% | 85.1% |
| destructive | 5 | 5 | 5 | 100.0% | 100.0% | 100.0% |
| external_communication | 10 | 23 | 9 | 90.0% | 39.1% | 40.2% |
| privilege_change | 1 | 2 | 1 | 100.0% | 50.0% | 65.9% |
| code_execution | 0 | 1 | 0 | - | 0.0% | 0.0% |
| public_exposure | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |
| financial_data_read | 1 | 2 | 1 | 100.0% | 50.0% | 65.9% |
| scheduled | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |
| bulk | 20 | 20 | 20 | 100.0% | 100.0% | 100.0% |
| pii_access | 25 | 17 | 16 | 64.0% | 94.1% | 63.4% |

## twilio

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| money_moving | 33 | 46 | 33 | 100.0% | 71.7% | 83.0% |
| destructive | 172 | 176 | 172 | 100.0% | 97.7% | 98.6% |
| external_communication | 9 | 168 | 9 | 100.0% | 5.4% | 8.8% |
| privilege_change | 126 | 107 | 96 | 76.2% | 89.7% | 80.4% |
| code_execution | 46 | 80 | 46 | 100.0% | 57.5% | 71.5% |
| public_exposure | 4 | 88 | 1 | 25.0% | 1.1% | 1.5% |
| financial_data_read | 164 | 183 | 158 | 96.3% | 86.3% | 89.5% |
| scheduled | 4 | 30 | 0 | 0.0% | 0.0% | -0.6% |
| bulk | 215 | 279 | 215 | 100.0% | 77.1% | 83.5% |
| pii_access | 15 | 86 | 15 | 100.0% | 17.4% | 28.1% |
| credential_access | 344 | 345 | 343 | 99.7% | 99.4% | 99.4% |
| data_export | 0 | 2 | 0 | - | 0.0% | 0.0% |

## zendesk

| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |
|---|---:|---:|---:|---:|---:|---:|
| destructive | 21 | 20 | 19 | 90.5% | 95.0% | 91.0% |
| external_communication | 4 | 18 | 4 | 100.0% | 22.2% | 32.3% |
| privilege_change | 14 | 13 | 13 | 92.9% | 100.0% | 95.8% |
| code_execution | 6 | 9 | 6 | 100.0% | 66.7% | 78.6% |
| public_exposure | 2 | 8 | 1 | 50.0% | 12.5% | 17.6% |
| scheduled | 0 | 4 | 0 | - | 0.0% | 0.0% |
| bulk | 49 | 50 | 49 | 100.0% | 98.0% | 98.2% |
| pii_access | 15 | 6 | 6 | 40.0% | 100.0% | 53.5% |
| credential_access | 4 | 4 | 4 | 100.0% | 100.0% | 100.0% |
| data_export | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |
