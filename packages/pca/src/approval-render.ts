import { b64u, decodeB64uStrict, hashCanonical, sha256, utf8 } from './hash';
import { closedMembers, isBoundedString, isDigest, isPlainObject, isSafeInt } from './intent-artifacts';

/**
 * WHAT YOU SEE IS WHAT YOU SIGN (track K7, security contract C-460..C-465).
 *
 * An approval used to sign the digest of the action; what the human SAW was whatever the wallet or channel drew. The approval now
 * commits to the canonical render of the action: the deterministic, locale-free field list `R` (see `@atlasauth/pca-actions`
 * `renderApproval`). The challenge the approver's authenticator signs, and the member an escalation answer carries, is
 *
 *     challenge = SHA-256( "atlas-pca/approval-challenge/v1" 0x00 || action_digest (32 bytes) || H(R) (32 bytes) )
 *     H(R)      = hashCanonical({ d: "atlas-pca/approval-render/v1", render: R })
 *
 * The approver client re-renders from the pinned definition and refuses to sign on mismatch; the verifier recomputes `H(R)` from
 * the executed parameters and its own definition and refuses on mismatch. A model never produces R.
 */

export const APPROVAL_RENDER_DOMAIN = 'atlas-pca/approval-render/v1';
export const APPROVAL_CHALLENGE_DOMAIN = 'atlas-pca/approval-challenge/v1\0';
export const APPROVAL_RENDER_KIND = 'pca-approval-render';
export const MAX_RENDER_FIELDS = 64;

export type RenderUnit = { kind: 'money'; ccy: string; exp: number } | { kind: 'count' | 'bytes' | 'duration' | 'ratio' };

export interface RenderField {
  /** The parameter name. */
  id: string;
  /** The parameter role (`money.amount`, `party.payee`, ...) or `param`. */
  class: string;
  /** The parameter value, verbatim (strict-canonical JSON; money is an integer in minor units). */
  value: unknown;
  /** The unit, with the currency resolved to a code. */
  unit?: RenderUnit;
}

export interface ApprovalRender {
  v: 1;
  kind: typeof APPROVAL_RENDER_KIND;
  verb: string;
  /** Digest of the definition the render was made from. */
  def_digest: string;
  /** True unless the definition carries a valid signed confirmation: single-tap approval is then forbidden. */
  unreviewed: boolean;
  /** Every parameter that was supplied, sorted by id (code point order). Nothing is omitted. */
  fields: RenderField[];
}

const FIELD_REQUIRED = ['id', 'class', 'value'] as const;

/** Null if `r` is a well-formed render (closed members, sorted unique ids, bounded). */
export function approvalRenderShapeError(r: unknown): string | null {
  if (!isPlainObject(r)) return 'render must be an object';
  const e = closedMembers(r, ['v', 'kind', 'verb', 'def_digest', 'unreviewed', 'fields'], [], 'render');
  if (e) return e;
  if (r.v !== 1 || r.kind !== APPROVAL_RENDER_KIND) return 'not a pca-approval-render v1';
  if (!isBoundedString(r.verb, 128)) return 'verb must be a bounded string';
  if (!isDigest(r.def_digest)) return 'def_digest must be canonical base64url (32 bytes)';
  if (typeof r.unreviewed !== 'boolean') return 'unreviewed must be a boolean';
  if (!Array.isArray(r.fields) || r.fields.length > MAX_RENDER_FIELDS) return `fields must be an array of at most ${MAX_RENDER_FIELDS}`;
  let prev: string | undefined;
  for (const f of r.fields as unknown[]) {
    if (!isPlainObject(f)) return 'a field must be an object';
    const fe = closedMembers(f, FIELD_REQUIRED, ['unit'], 'field');
    if (fe) return fe;
    if (!isBoundedString(f.id, 192) || !isBoundedString(f.class, 128)) return 'field id and class must be bounded strings';
    if (prev !== undefined && !(prev < (f.id as string))) return 'fields must be sorted by id and unique';
    prev = f.id as string;
    if (f.unit !== undefined) {
      if (!isPlainObject(f.unit)) return 'unit must be an object';
      const k = f.unit.kind;
      if (k === 'money') {
        if (closedMembers(f.unit, ['kind', 'ccy', 'exp'], [], 'unit') || !isBoundedString(f.unit.ccy, 16) || !isSafeInt(f.unit.exp) || f.unit.exp < 0 || f.unit.exp > 18) return 'a money unit needs ccy and exp';
      } else if (!(k === 'count' || k === 'bytes' || k === 'duration' || k === 'ratio') || closedMembers(f.unit, ['kind'], [], 'unit')) return 'unknown unit';
    }
  }
  return null;
}

/** H(R). Throws on a malformed render (fail closed: a digest is never made over a shapeless value). */
export function approvalRenderDigest(render: ApprovalRender): string {
  const e = approvalRenderShapeError(render);
  if (e) throw new Error(`approvalRenderDigest: ${e}`);
  return hashCanonical({ d: APPROVAL_RENDER_DOMAIN, render });
}

/** The 32-byte approval challenge for (action digest, render digest). Accepts the action digest as b64u or raw bytes. */
export function approvalChallenge(actionDigest: string | Uint8Array, renderDigest: string): Uint8Array {
  const a = typeof actionDigest === 'string' ? decodeB64uStrict(actionDigest, 32) : actionDigest.length === 32 ? actionDigest : null;
  const r = decodeB64uStrict(renderDigest, 32);
  if (a === null || r === null) throw new Error('approvalChallenge: both digests must be canonical 32-byte values');
  const dom = utf8(APPROVAL_CHALLENGE_DOMAIN);
  const m = new Uint8Array(dom.length + 64);
  m.set(dom, 0);
  m.set(a, dom.length);
  m.set(r, dom.length + 32);
  return sha256(m);
}

export const approvalChallengeB64u = (actionDigest: string | Uint8Array, renderDigest: string): string => b64u(approvalChallenge(actionDigest, renderDigest));

/** A short, speakable word-string of H(R) (8 words from a 256-word list), so a push and the original screen can be matched by eye. */
export const BINDING_WORDS = [
  'able', 'acid', 'aged', 'also', 'area', 'army', 'atom', 'aunt', 'away', 'baby', 'back', 'ball', 'band', 'bank', 'base', 'bath',
  'bear', 'beat', 'beef', 'bell', 'belt', 'bend', 'bird', 'blue', 'boat', 'body', 'bold', 'bone', 'book', 'boot', 'born', 'both',
  'bowl', 'bulb', 'burn', 'bush', 'busy', 'cafe', 'cake', 'calm', 'camp', 'card', 'care', 'cart', 'case', 'cash', 'cast', 'cave',
  'cell', 'chat', 'chef', 'chip', 'city', 'clay', 'clip', 'club', 'coal', 'coat', 'code', 'coin', 'cold', 'cook', 'cool', 'cope',
  'copy', 'cord', 'core', 'cost', 'crew', 'crop', 'dark', 'data', 'date', 'dawn', 'deal', 'dear', 'deck', 'deep', 'deer', 'desk',
  'dial', 'dice', 'diet', 'dish', 'dive', 'door', 'dose', 'down', 'draw', 'drop', 'drum', 'duck', 'dust', 'duty', 'each', 'earn',
  'east', 'easy', 'edge', 'echo', 'else', 'even', 'ever', 'exit', 'face', 'fact', 'fair', 'fall', 'farm', 'fast', 'fate', 'fern',
  'file', 'fill', 'film', 'find', 'fine', 'fire', 'firm', 'fish', 'five', 'flag', 'flat', 'flow', 'foam', 'fold', 'folk', 'food',
  'foot', 'fork', 'form', 'fort', 'four', 'free', 'frog', 'fuel', 'full', 'fund', 'gain', 'game', 'gate', 'gear', 'gift', 'girl',
  'glad', 'glow', 'goat', 'gold', 'golf', 'good', 'grab', 'gray', 'grid', 'grip', 'grow', 'gulf', 'hair', 'half', 'hall', 'hand',
  'hard', 'harp', 'hawk', 'head', 'heat', 'help', 'herb', 'hill', 'hint', 'hold', 'hole', 'home', 'hood', 'hook', 'hope', 'horn',
  'host', 'hour', 'huge', 'hunt', 'idea', 'inch', 'iron', 'isle', 'item', 'jade', 'jazz', 'join', 'joke', 'jump', 'jury', 'just',
  'keen', 'keep', 'kind', 'king', 'kite', 'knee', 'knot', 'lake', 'lamp', 'land', 'lane', 'last', 'late', 'lawn', 'lead', 'leaf',
  'lean', 'left', 'lens', 'less', 'lift', 'lime', 'line', 'link', 'lion', 'list', 'live', 'load', 'loan', 'lock', 'logo', 'long',
  'loop', 'lord', 'loud', 'love', 'luck', 'lung', 'made', 'mail', 'main', 'mask', 'mass', 'mate', 'meal', 'melt', 'menu', 'mild',
  'milk', 'mind', 'mint', 'mole', 'moon', 'more', 'moss', 'move', 'much', 'nail', 'navy', 'neat', 'neck', 'nest', 'news', 'nice',
] as const;

export function bindingWords(renderDigest: string): string {
  const r = decodeB64uStrict(renderDigest, 32);
  if (r === null) throw new Error('bindingWords: render digest must be a canonical 32-byte value');
  return Array.from(r.subarray(0, 6), (b) => BINDING_WORDS[b]!).join('-');
}
