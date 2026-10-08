# PCA diagrams: Mermaid blocks

Paste any block into GitHub markdown. Each block is identical to the matching `.mmd` file.

## authN, authZ, authF

The three questions (who are you, what may you do, is this action faithful), their credentials, and PCA composing on top.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#f1edff', 'primaryBorderColor': '#7c5cff', 'primaryTextColor': '#1c1c1f', 'lineColor': '#5f5f6b', 'fontFamily': 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif'}}}%%
flowchart LR
  subgraph N["authN: Who are you?"]
    direction TB
    N1["WebAuthn / passkeys"]
    N2["Credential: assertion<br/>signed, origin-bound challenge"]
    N3["Proves: a human holds the device key"]
    N1 --> N2 --> N3
  end
  subgraph Z["authZ: What may you do?"]
    direction TB
    Z1["OAuth 2.1 + PKCE + PoP"]
    Z2["Credential: access token<br/>bearer or sender-constrained"]
    Z3["Proves: scopes granted at time 0"]
    Z1 --> Z2 --> Z3
  end
  subgraph F["authF: Is this action faithful?"]
    direction TB
    F1["Proof-Carrying Authority"]
    F2["Credential: PCActn<br/>proof-carrying action"]
    F3["Proves: plan node + policy + attenuating chain<br/>+ threshold + budget + ledger"]
    F1 --> F2 --> F3
  end
  N ==>|"+"| Z ==>|"+"| F
  BASE["PCA composes on top<br/>rung 0 = OAuth PoP, humans keep passkeys"]
  F -.- BASE
  classDef pca fill:#f1edff,stroke:#7c5cff,stroke-width:2px,color:#1c1c1f
  classDef base fill:#e5fbf1,stroke:#34e5a0,stroke-width:2px,color:#1c1c1f
  class F1,F2,F3 pca
  class BASE base
```

## The PCA loop

Sequence: mint, attenuate, commit plan, emit PCActn, decide, verify, anchor, with the t = 3 step-up and out-of-plan reject branches.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#f1edff', 'primaryBorderColor': '#7c5cff', 'primaryTextColor': '#1c1c1f', 'lineColor': '#5f5f6b', 'signalColor': '#5f5f6b', 'noteBkgColor': '#e5fbf1', 'noteBorderColor': '#34e5a0', 'fontFamily': 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif'}}}%%
sequenceDiagram
  participant P as Principal
  participant A as Agent
  participant G as Policy VM / Guardian (Atlas)
  participant R as Resource Server
  participant L as Transparency Ledger

  P->>P: mintGrant(): sign envelope with root key
  P->>A: Root Intent Grant (holder = agent key)
  A->>A: attenuate / delegate (caveats only narrow)
  A->>A: commitPlan(): Merkle root Π
  A->>G: commit plan root Π

  loop for each action
    A->>A: buildPCActn(): plan proof, chain, counter, risk claim, sig
    A->>G: POST /v1/pca/actions (PCActn)
    G->>G: decide(): predicates, caveats, r(A), budget
    alt in plan, in policy, t ≤ 2
      G-->>A: guardian share released (auto)
      A->>R: PCActn + threshold shares
      R->>R: verifyPCActn(): plan, chain, threshold, revocation, counter
      R->>L: anchor (salted commit)
      L-->>R: receipt + inclusion proof
      R-->>A: ALLOWED + receipt
    else t = 3, risk above θ₂: STEP-UP
      G-->>A: 202 step_up_required (held, not anchored)
      P->>G: device co-sign: POST /stepups/:id/cosign
      G->>G: re-verify in full, recharge budget (human touch)
      G->>L: anchor
      G-->>A: approved + receipt (agent polls)
    else action not in plan (node not in Π)
      A->>G: PCActn for an unplanned action
      G->>G: no plan inclusion proof, L1 fails
      G-->>A: REJECT: denied, no share released
    end
  end
```

## Architecture

Principal, agent and sub-agents, guardian (Atlas), resource server with its hooks, transparency ledger and TEE attestation, with the capability chain and PCActn flows.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#f1edff', 'primaryBorderColor': '#7c5cff', 'primaryTextColor': '#1c1c1f', 'lineColor': '#5f5f6b', 'fontFamily': 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif'}}}%%
flowchart TB
  P["Principal<br/>root key, device share"]
  subgraph TEE["L0: TEE-attested workload"]
    AG["Agent<br/>holds one share, commits plan"]
    S1["Sub-agent A<br/>sub is within parent"]
    S2["Sub-agent B<br/>sub is within parent"]
    AG -->|"attenuate / delegate"| S1
    AG --> S2
  end
  G["Guardian (Atlas)<br/>Policy VM, guardian share, trust budget"]
  ATT["Attestation<br/>TEE quote: model, weights, runtime"]
  subgraph RS["Resource Server: verifyPCActn / requirePCA"]
    V["Verifier<br/>plan, chain, signature, counter"]
    H1["hook: attestation"]
    H2["hook: threshold"]
    H3["hook: revocation"]
    H4["hook: zk"]
    V --- H1
    V --- H2
    V --- H3
    V --- H4
  end
  L["Transparency Ledger<br/>Merkle log, revocation set, beacons"]
  P -->|"Root Intent Grant (capability chain)"| AG
  P -.->|"device co-sign (t = 3)"| G
  AG -->|"PCActn"| G
  G -.->|"guardian share"| AG
  AG ==>|"PCActn"| V
  ATT -.->|"measures"| TEE
  ATT -.->|"quote"| H1
  V -->|"anchor"| L
  L -.->|"revocation root + proofs"| H3
  G -.->|"witness heads"| L
  classDef role fill:#fff,stroke:#d8d8e0,stroke-width:1.5px,color:#1c1c1f
  classDef guard fill:#f1edff,stroke:#7c5cff,stroke-width:2px,color:#1c1c1f
  classDef good fill:#e5fbf1,stroke:#34e5a0,stroke-width:2px,color:#1c1c1f
  class P,AG,S1,S2,V role
  class G,H1,H2,H3,H4 guard
  class ATT,L good
```

## The PCA stack

Layers L0 to L5, one proof clause each, plus the optimistic and zero-knowledge accelerants.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#f1edff', 'primaryBorderColor': '#7c5cff', 'primaryTextColor': '#1c1c1f', 'lineColor': '#5f5f6b', 'fontFamily': 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif'}}}%%
flowchart BT
  subgraph STACK["PCA stack: each layer is one clause of the proof"]
    direction BT
    L0["L0 · Attestation-derived identity<br/>Is the actor the attested workload?"]
    L1["L1 · Plan commitment<br/>Is the action a node of an authorized plan?"]
    L2["L2 · Policy as co-signer<br/>Did the policy cryptographically take part?"]
    L3["L3 · Risk-adaptive threshold, trust budget<br/>Is friction proportionate, is budget left?"]
    L4["L4 · Provenance taint<br/>Is the lineage clean of untrusted influence?"]
    L5["L5 · Ledger, revocation, beacons<br/>Unrevoked, fresh, anchored?"]
    L0 --> L1 --> L2 --> L3 --> L4 --> L5
  end
  subgraph ACC["Optional accelerants"]
    OPT["Optimistic + fraud proofs<br/>latency: bonded claim, challenge window"]
    ZK["Zero-knowledge compliance proofs<br/>privacy: hide plan, policy, reasoning"]
  end
  OPT -.-> L3
  ZK -.-> L4
  classDef layer fill:#fff,stroke:#7c5cff,stroke-width:1.5px,color:#1c1c1f
  classDef base fill:#f1edff,stroke:#7c5cff,stroke-width:2px,color:#1c1c1f
  classDef acc fill:#e5fbf1,stroke:#34e5a0,stroke-width:2px,color:#1c1c1f
  class L1,L2,L3,L4,L5 layer
  class L0 base
  class OPT,ZK acc
```

## Trust budget

Control-system view: risk sensor, threshold actuator, depleting budget with human recharge, and the sum r <= bMax / kappa bound.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#f1edff', 'primaryBorderColor': '#7c5cff', 'primaryTextColor': '#1c1c1f', 'lineColor': '#5f5f6b', 'fontFamily': 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif'}}}%%
flowchart LR
  SP["Setpoint<br/>operate within sanctioned intent"] --> SE["Sensor<br/>risk functional r(A)"]
  SE --> C["Controller<br/>t(r) and admit(r, B)"]
  C --> AC["Actuator<br/>required threshold t"]
  AC --> PL["Plant<br/>the agent"]
  PL -.->|"next action measured again"| SE
  B[("Trust budget B in [0, bMax]")]
  C <-->|"reads B, debits κ·r"| B
  LK["Passive leak<br/>B decreases by λ·Δt"] --> B
  HU["Human step-up<br/>principal device co-sign"] -->|"recharge +ρ (only source)"| B
  AC -.->|"t = 3"| HU
  BND["Safety bound<br/>Σ rᵢ ≤ bMax / κ between recharges"]
  B --- BND
  classDef sense fill:#f1edff,stroke:#7c5cff,stroke-width:2px,color:#1c1c1f
  classDef act fill:#e5fbf1,stroke:#34e5a0,stroke-width:2px,color:#1c1c1f
  classDef bound fill:#1c1c1f,stroke:#1c1c1f,color:#ffffff
  class SE sense
  class AC,HU act
  class BND bound
```

## Threshold and step-up

Escalation t = 1, 2, 3 by risk, the hosted step-up flow, and multi-signature versus FROST aggregation.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#f1edff', 'primaryBorderColor': '#7c5cff', 'primaryTextColor': '#1c1c1f', 'lineColor': '#5f5f6b', 'fontFamily': 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif'}}}%%
flowchart LR
  R["risk r(A)"] --> D1{"r ≤ θ₁ (0.25)?"}
  D1 -->|"yes"| T1["t = 1, proof: claim<br/>agent signs<br/>zero friction"]
  D1 -->|"no"| D2{"r ≤ θ₂ (0.60)?"}
  D2 -->|"yes"| T2["t = 2, proof: standard<br/>agent + guardian (auto)<br/>Policy VM must judge compliant"]
  D2 -->|"no"| T3["t = 3, proof: strong<br/>agent + guardian + principal device<br/>a human co-signs"]
  T3 --> SU["202 step_up_required<br/>held 15 min, not anchored"]
  SU --> CO["Principal device signs thresholdMessage<br/>POST /stepups/:id/cosign"]
  CO --> RV["Re-verify in full<br/>anchor, recharge budget B"]
  T1 --> AGG
  T2 --> AGG
  RV --> AGG
  AGG["Aggregation<br/>multi-signature (default): t distinct Ed25519 signatures<br/>FROST (optional): one Ed25519 signature under a group key"]
  classDef t1 fill:#e5fbf1,stroke:#34e5a0,stroke-width:2px,color:#1c1c1f
  classDef t2 fill:#f1edff,stroke:#7c5cff,stroke-width:2px,color:#1c1c1f
  classDef t3 fill:#7c5cff,stroke:#7c5cff,color:#ffffff
  class T1 t1
  class T2 t2
  class T3 t3
```


## Cryptographic backends

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#f1edff', 'primaryBorderColor': '#7c5cff', 'primaryTextColor': '#1c1c1f', 'lineColor': '#5f5f6b', 'fontFamily': 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif'}}}%%
flowchart TB
  subgraph SIG["Signatures — crypto-agile suite registry (every signed surface)"]
    direction LR
    S_C["Classical<br/>Ed25519"]
    S_L["Lattice PQ<br/>ML-DSA-65 / ML-DSA-87"]
    S_H["Hash PQ<br/>SLH-DSA-128f / 256s"]
    S_X["Hybrid (fail-closed, both req.)<br/>Ed25519+ML-DSA · +SLH · nested"]
  end
  SURF["surfaces: leaf PCActn · capability-chain hops · FROST group sig (+ PQ ML-DSA co-sign)<br/>· transparency STH · C2SP witnesses · revocation epochs · beacons · bond settlements · safety cert · judge verdicts · attestation"]
  SIG --> SURF

  subgraph ZK["Zero-knowledge proof backends"]
    direction LR
    Z_G["Groth16<br/>BN254 → BLS12-381<br/>Policy-VM circuit"]
    Z_S["STARK (transparent, PQ)<br/>Winterfell + Plonky3<br/>witness ⟂ action commit"]
    Z_V["zkVM — RISC Zero<br/>full Policy-VM,<br/>canonical-JSON sha256"]
    Z_F["Folding IVC — Nova/HyperNova<br/>Poseidon chain-digest<br/>Σcost ≤ bMax"]
  end

  subgraph MPC["Policy-VM under MPC (malicious, dishonest-majority)"]
    direction LR
    M_O["MASCOT no-dealer offline<br/>+ SPDZ online (IT MACs)"]
    M_B["Base OT: malicious EC (Chou–Orlandi+Schnorr)<br/>· ML-KEM KEM-OT · hybrid<br/>· ENDEMIC Module-LWE OT (PQ-malicious)"]
    M_W["constant-time<br/>curve25519 WASM core"]
  end

  subgraph ATT["Attestation roots — N-of-M policy, each its own suite"]
    direction LR
    A_AMD["AMD SEV-SNP<br/>classical"]
    A_INT["Intel TDX/DCAP<br/>classical"]
    A_NV["NVIDIA GPU-CC<br/>classical · model runtime"]
    A_PQ["PQ software / HSM<br/>ML-DSA / SLH-DSA — POST-QUANTUM"]
    A_PUF["PUF<br/>unclonable (fuzzy extractor)"]
  end

  subgraph PRIM["Primitives"]
    direction LR
    P_E["Entropy<br/>QRNG mix (HKDF) + CSPRNG"]
    P_H["Hashes<br/>SHA-256/384 · Poseidon · Blake3"]
    P_K["KEM<br/>X25519+ML-KEM-768 hybrid"]
  end

  classDef pq fill:#f1edff,stroke:#7c5cff,stroke-width:2px,color:#1c1c1f
  classDef cl fill:#fff,stroke:#d8d8e0,stroke-width:1.5px,color:#1c1c1f
  classDef good fill:#e5fbf1,stroke:#34e5a0,stroke-width:2px,color:#1c1c1f
  class S_L,S_H,S_X,A_PQ,Z_S,Z_V,M_B pq
  class S_C,A_AMD,A_INT,A_NV cl
  class P_E,P_H,P_K,A_PUF,Z_G,Z_F,M_O,M_W good

```
