// pca-state adapter over the durable file store whose FIRST child process to open a handle exits before racing.
import { openSync, closeSync } from 'node:fs';
import { durablePcaStateStore } from '@atlasauth/pca';
import { openDurableState } from '@atlasauth/pca/durable-state';

export function createPcaStateAdapter({ dir, marker, parent }) {
  return {
    name: 'fixture: durable file store, one worker dies at start',
    capabilities: { durable: true, shared: true },
    async open() {
      if (String(process.pid) !== parent) {
        let first = false;
        try {
          closeSync(openSync(marker, 'wx'));
          first = true;
        } catch {}
        if (first) process.exit(3);
      }
      return { store: durablePcaStateStore(await openDurableState({ dir })) };
    },
  };
}
