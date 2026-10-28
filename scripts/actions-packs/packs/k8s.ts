import { openApiPack } from '../lib/factory';
import { snake } from '../lib/naming';

// Kubernetes API verbs: k8s.<group>.<resource>.<action>[_<subresource>]. Only stable (non beta/alpha) API versions, no deprecated watch paths.
const ACTIONS: Record<string, string> = { get: 'get', list: 'list', create: 'create', post: 'create', put: 'update', update: 'update', patch: 'patch', delete: 'delete', deletecollection: 'delete_collection', connect: 'connect', watch: 'watch', watchlist: 'watch' };

function rename(_segs: string[], info: { method: string; path: string; tags: string[] }, raw: Record<string, unknown>): string[] {
  const act = String(raw['x-kubernetes-action'] ?? '');
  let p = info.path.split('/').filter(Boolean);
  let group = 'core';
  if (p[0] === 'api') p = p.slice(2);
  else if (p[0] === 'apis') { group = snake((p[1] ?? 'core').split('.')[0]!); p = p.slice(3); }
  if (p[0] === 'namespaces' && p[1]?.startsWith('{') && p.length > 2) p = p.slice(2);
  const statics = p.filter((x) => !x.startsWith('{'));
  const hasName = p.some((x, i) => i > 0 && x.startsWith('{')) || (p.length >= 2 && p[1]?.startsWith('{'));
  const plural = snake(statics[0] ?? 'api');
  const sub = statics.slice(1).map(snake).join('_');
  let a = ACTIONS[act] ?? snake(act || info.method);
  if (a === 'get' && !hasName && statics.length === 1) a = 'list';
  if (info.method === 'POST' && statics.length >= 2 && a === 'create') a = 'create';
  if (a === 'connect') return [group, plural, [a, sub, info.method.toLowerCase(), p.some((x) => x === '{path}') ? 'with_path' : ''].filter(Boolean).join('_')];
  return [group, plural, sub ? `${a}_${sub}` : a];
}

export default openApiPack({
  name: 'k8s',
  ns: 'k8s',
  redistribution: 'permitted',
  licence_notes: 'The Kubernetes OpenAPI description is Apache-2.0 licensed. Verbs, parameter names/types/bounds and the operation summaries are carried; the trait review is ours.',
  config_file: __filename,
  oa: () => ({ naming: 'path', flatten: false, include: /^\/api(s\/[^/]+)?\/v\d+(\/|$)(?!.*\/watch\/)/, exclude: /\/(watch)\/|^\/apis\/[^/]+\/v\d+(alpha|beta)|^\/logs|^\/version|^\/openid/, rename }),
  build: () => ({
    ns: 'k8s',
    vendorTitles: true,
    rules: [
      { re: /^k8s\.core\.pods\.(connect_(exec|attach|portforward)|create_(exec|attach|portforward))/, on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: /\.connect(_|$)/, on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: /^k8s\.rbac\.\w+\.(delete|delete_collection)$/, on: 'verb', patch: { effects: ['delete', 'privilege'], rev: 'irreversible' } },
      { re: /^k8s\.rbac\.\w+\.(create|update|patch)/, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: /^k8s\.core\.serviceaccounts\.create_token$/, on: 'verb', patch: { effects: ['create'], rev: 'reversible', traits: ['pca.credential_access'] } },
      { re: /^k8s\.certificates\.certificatesigningrequests\.(update|patch)_approval$/, on: 'verb', patch: { effects: ['privilege'], rev: 'irreversible' } },
      { re: /^k8s\.core\.pods\.create_eviction$/, on: 'verb', patch: { effects: ['delete'], rev: 'irreversible' } },
      { re: /^k8s\.(authentication|authorization)\.\w+\.create/, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
    ],
    declare: (_v, _op, verb) => [
      ...(/^k8s\.core\.secrets\./.test(verb) ? ['pca.credential_access'] : []),
      ...(/^k8s\.(apps|batch|core|networking|storage|policy)\.\w+\.(create|update|patch|delete|delete_collection)/.test(verb) ? ['pca.infra_mutation'] : []),
    ],
  }),
});
