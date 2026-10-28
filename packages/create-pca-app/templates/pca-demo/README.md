# __PCA_APP_NAME__

The whole Proof-Carrying Authority story, running locally: no accounts, no Docker, no API keys.

```bash
npm install
npm start          # colorized walkthrough; exit code 1 if any outcome deviates
npm run step       # pause before each step
npm run json       # machine-readable result
```

`story.mjs` is the script: read it top to bottom. It starts a real resource server (`node:http` +
`withPCA` from `@atlasauth/pca-fetch`), a guardian that FROST-signs 3-of-5, and an agent built with
the `agent()` facade, then plays: in-plan allow, off-plan deny, a t=3 step-up, replay, tampering
(bit-flipped signature, widened delegation, swapped audience), budget exhaustion, an attenuated
sub-agent, and an offline-verified receipt with a transparency-log inclusion proof.

To protect your own route, copy the `guard` options object in `story.mjs` (`audience`, `resolveGrant`,
`budgetStore`, `hooks`, `context`) into your server.
