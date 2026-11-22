# Catalog packs

Each pack is a set of action definitions generated or hand-written from a public API description, with the machine's best guess at each action's traits.

**Those traits are hints.** A pack is inert-strict until a person reviews it: every action in it is unconfirmed, so it is treated as having every trait (money, deletion, outbound messages, code execution, privilege change, credentials, public exposure ...) and needs the strictest step-up, whatever the pack's labels say. Only a confirmation signed by a reviewer key you pin sets an action's real traits.

Review a whole pack in one pass, riskiest first (nothing is signed without `--yes`):

```sh
pca actions confirm --pack stripe --origin any --packs-dir packs --kid rev-1
pca actions confirm --pack stripe --origin any --kid rev-1 --reviewer-key <32-byte base64url secret> --yes   # writes stripe.reviewed.yaml
```

Then list the reviewer's public key under `reviewers` in `pca.config.json` (or `ctx.reviewers` for a verifier). Licences of the sources are recorded in `LICENCES.md`.
