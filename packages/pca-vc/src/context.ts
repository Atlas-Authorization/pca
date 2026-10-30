import { createHash } from 'node:crypto';

/**
 * The JSON-LD context for `AgentPassportCredential`, bundled so a verifier resolves it offline and never has to fetch
 * the IRI. Terms are `@protected`: a credential or a later context cannot redefine them. Serve this exact document
 * (byte for byte, as `application/ld+json`) at `https://atlasauth.net/credentials/agent-passport/v1` for verifiers that
 * do fetch; pin it with {@link AGENT_PASSPORT_CONTEXT_DIGEST}.
 */
const V = 'https://atlasauth.net/credentials/agent-passport/v1#';
const XSD = 'http://www.w3.org/2001/XMLSchema#';
export const AGENT_PASSPORT_CONTEXT_DOC = Object.freeze({
  '@context': {
    '@protected': true,
    AgentPassportCredential: {
      '@id': `${V}AgentPassportCredential`,
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        passport_id: { '@id': `${V}passportId`, '@type': `${XSD}string` },
        model_id: { '@id': `${V}modelId`, '@type': `${XSD}string` },
        operator: { '@id': `${V}operator`, '@type': `${XSD}string` },
        hardware_rooted: { '@id': `${V}hardwareRooted`, '@type': `${XSD}boolean` },
        weights_measured: { '@id': `${V}weightsMeasured`, '@type': `${XSD}boolean` },
        issued_at: { '@id': `${V}issuedAt`, '@type': `${XSD}integer` },
        weights_digest: { '@id': `${V}weightsDigest`, '@type': `${XSD}string` },
        system_prompt_digest: { '@id': `${V}systemPromptDigest`, '@type': `${XSD}string` },
        tool_manifest_digest: { '@id': `${V}toolManifestDigest`, '@type': `${XSD}string` },
        runtime_measurement: { '@id': `${V}runtimeMeasurement`, '@type': `${XSD}string` },
        _sd: { '@id': `${V}selectiveDisclosureDigest`, '@container': '@set' },
      },
    },
  },
});

const canonical = (v: unknown): string => {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`;
};

/** SHA-256 (hex) of the key-sorted JSON of {@link AGENT_PASSPORT_CONTEXT_DOC}; changes whenever any term changes. */
export const AGENT_PASSPORT_CONTEXT_DIGEST: string = createHash('sha256').update(canonical(AGENT_PASSPORT_CONTEXT_DOC)).digest('hex');

/** A document loader for JSON-LD processors: the bundled document for its IRI, `undefined` for anything else (never fetched). */
export function resolveAgentPassportContext(iri: string): typeof AGENT_PASSPORT_CONTEXT_DOC | undefined {
  return iri === 'https://atlasauth.net/credentials/agent-passport/v1' ? AGENT_PASSPORT_CONTEXT_DOC : undefined;
}
