# __PCA_APP_NAME__

Define your actions once; everything else is derived from the definition: the signed action schema, the operation binding, the policy card text, the risk and escalation of each action.

```sh
npm install
npm run lint        # 24 rules; --strict also fails on warnings
npm test            # runs the examples in actions/acme.yaml and the generic property checks
npm run explain     # what the action is, how risky it is, and what a grant must carry
npm run build       # .pca/: schema.json, pack.json, cards.json, ontology.json, mcp.json, types.d.ts
npm run digest      # the TypeScript builder and the YAML give the same digest
```

Sign and publish with a key you control:

```sh
npx pca keygen                                  # a throwaway dev key
npx pca actions sign --kid site-1 --key <secret>
npx pca actions publish                         # writes .pca/.well-known/pca-actions.json
```

Nothing here authorizes anything: the resource server's verifier decides. A definition you did not review is treated as the most restrictive kind of action until you confirm it.
