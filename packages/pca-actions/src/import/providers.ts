// providers.ts - model adapters for `--suggest model`: a pinned model id on a named provider, the API key read from the
// environment at call time (never a flag, never printed, never stored, never put in an error). The request is exactly the
// names-and-types prompt of ./model; the answer is parsed against the closed trait vocabulary there. `fetchImpl` is injectable
// so tests use a recorded fake.

import { ActionKitError } from '../def';
import type { ModelAdapter, ModelRequest } from './model';

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export const PROVIDERS = ['anthropic', 'openai'] as const;
export type Provider = (typeof PROVIDERS)[number];

const KEY_ENV: Readonly<Record<Provider, string>> = { anthropic: 'ANTHROPIC_API_KEY', openai: 'OPENAI_API_KEY' };
const URL_OF: Readonly<Record<Provider, string>> = { anthropic: 'https://api.anthropic.com/v1/messages', openai: 'https://api.openai.com/v1/chat/completions' };

export interface ModelEnvConfig {
  provider: Provider;
  model: string;
  /** Present only to be handed to the adapter; never serialised. */
  readonly apiKey: string;
}

/**
 * Read the model assist configuration. `model` and `provider` come from flags or ATLAS_PCA_SUGGEST_MODEL / ATLAS_PCA_SUGGEST_PROVIDER;
 * the model must be named explicitly (a pinned id: no default that silently changes). The key comes only from the provider's env var.
 */
export function modelConfigFromEnv(env: Record<string, string | undefined>, flags: { model?: string; provider?: string } = {}): ModelEnvConfig {
  const provider = (flags.provider ?? env.ATLAS_PCA_SUGGEST_PROVIDER ?? 'anthropic') as Provider;
  if (!(PROVIDERS as readonly string[]).includes(provider)) throw new ActionKitError('bad_model_config', `unknown provider (one of ${PROVIDERS.join(', ')})`);
  const model = flags.model ?? env.ATLAS_PCA_SUGGEST_MODEL;
  if (!model || !/^[A-Za-z0-9._:/-]{1,128}$/.test(model)) throw new ActionKitError('bad_model_config', '--model <pinned model id> (or ATLAS_PCA_SUGGEST_MODEL) is required');
  const apiKey = env[KEY_ENV[provider]];
  if (!apiKey) throw new ActionKitError('bad_model_config', `${KEY_ENV[provider]} is not set`);
  return Object.defineProperty({ provider, model } as ModelEnvConfig, 'apiKey', { value: apiKey, enumerable: false });
}

/** A ModelAdapter for the provider. Errors carry the HTTP status only: never the key, the request or the response body. */
export function providerAdapter(cfg: ModelEnvConfig, fetchImpl: FetchLike, timeoutMs = 30_000): ModelAdapter {
  return {
    id: `${cfg.provider}:${cfg.model}`,
    async complete(req: ModelRequest): Promise<string> {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), timeoutMs);
      try {
        const headers: Record<string, string> = { 'content-type': 'application/json' };
        let body: unknown;
        if (cfg.provider === 'anthropic') {
          headers['x-api-key'] = cfg.apiKey;
          headers['anthropic-version'] = '2023-06-01';
          body = { model: cfg.model, max_tokens: 512, temperature: req.temperature, system: req.system, messages: [{ role: 'user', content: req.user }] };
        } else {
          headers.authorization = `Bearer ${cfg.apiKey}`;
          body = { model: cfg.model, max_tokens: 512, temperature: req.temperature, messages: [{ role: 'system', content: req.system }, { role: 'user', content: req.user }] };
        }
        let res;
        try {
          res = await fetchImpl(URL_OF[cfg.provider], { method: 'POST', headers, body: JSON.stringify(body), signal: ctl.signal });
        } catch {
          throw new Error(`${cfg.provider} request failed`);
        }
        if (!res.ok) throw new Error(`${cfg.provider} returned HTTP ${res.status}`);
        const j = (await res.json()) as { content?: { type?: string; text?: string }[]; choices?: { message?: { content?: string } }[] };
        const text = cfg.provider === 'anthropic' ? j.content?.find((c) => c.type === 'text')?.text : j.choices?.[0]?.message?.content;
        if (typeof text !== 'string') throw new Error(`${cfg.provider} returned no text`);
        return text;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
