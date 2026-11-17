// Shared helpers for the box scripts: resolve the workspace packages from where they are installed in the image.
import { createRequire } from 'node:module';

const fromProxy = createRequire('/repo/packages/pca-proxy/package.json');
export const pca = fromProxy('@atlasauth/pca');
export const YAML = fromProxy('yaml');
export const DATA = process.env.PCA_BOX_DATA ?? '/data';

import { readFileSync } from 'node:fs';
/** The public key of the reviewer who signs grants (pinned by the proxy as the only signer it accepts). */
export const reviewerPub = () => readFileSync(`${DATA}/keys/reviewer.pub`, 'utf8').trim();
