import { hashCanonical } from '@atlasauth/pca';
import { DEFAULT_CATALOG, type Catalog, type Reversibility } from '@atlasauth/pca/ext/research';
import { labelOf, numCells, type Dim, type Omega, type VerbSpace } from '@atlasauth/pca-intent';
import { catLabel, resolveCoords } from './box';
import { worstProvenance } from './friction';
import { frictionRank, type ActionValues, type CellCoords, type FrictionTier, type PartialSpec, type WebAuthnEvidence } from './wire';

/**
 * THE TRUSTED QUESTION CARD (§3.4 items 1-3). Rendering belongs to the wallet and is deterministic:
 * `renderCard(input)` is a pure function of the wallet's own outcome space, the cell coordinates, the site identity
 * verified from discovery, the principal's own signed statement, schema units, the friction tier and (for a
 * clarification) a closed-enum reason. Its input type has NO field for agent-authored text, so no agent sentence can
 * reach the human. Values of the concrete action are data, shown only in fixed slots: numbers formatted by unit, and a
 * string only when it is a value the wallet's own outcome space names (otherwise only its last four letters/digits, so
 * no sentence fits). The digest of the card (`rendered_digest`) goes into the signed answer, so an auditor can
 * re-render it from the same inputs and see exactly what the human saw.
 */

export const CARD_DOMAIN = 'atlas-pca/intent-card/v2';

export type Unit = { kind: 'money'; currency: string; exponent: number } | { kind: 'count' };

/** The closed reason enum of an agent clarification (§3.14), with the fixed label the card shows. */
export const CLARIFY_REASONS = ['ambiguous_parameter', 'multiple_options', 'price_changed', 'constraint_conflict', 'missing_value', 'other'] as const;
export type ClarifyReason = (typeof CLARIFY_REASONS)[number];
export const REASON_LABELS: Readonly<Record<ClarifyReason, string>> = {
  ambiguous_parameter: 'Your agent found a detail your request did not settle.',
  multiple_options: 'Your agent found several options that match.',
  price_changed: 'Your agent found that a price changed.',
  constraint_conflict: 'Your agent found that two parts of your request conflict.',
  missing_value: 'Your agent needs a value your request did not give.',
  other: 'Your agent needs a decision before it continues.',
};

export type CardKind = 'question' | 'clarification';

export interface CardInput {
  omega: Omega;
  verb: string;
  coords: CellCoords;
  /** The site as verified from its discovery document (origin) and the wallet's own directory (display name). */
  site: { origin: string; name: string };
  /** The principal's own words (the signed intent statement), quoted back. */
  statementText?: string;
  /** Value-dependent reversibility of the cell (from the signed schema). Default: the verb's, from Ω. */
  reversibility?: Reversibility;
  /** Units from the signed action schema, keyed by dimension path. */
  units?: Readonly<Record<string, Unit>>;
  /** The concrete action (or the representative of a canary or clarification candidate). */
  action?: ActionValues;
  friction: FrictionTier;
  kind: CardKind;
  reason?: ClarifyReason;
  locale?: 'en';
  catalog?: Catalog;
}

export interface CardFactV2 {
  key: string;
  label: string;
  text: string;
}

export type PartialSlotV2 = { path: string; kind: 'num'; lo: number; hi: number } | { path: string; kind: 'cat'; options: string[] };

export interface TrustedCard {
  v: 2;
  kind: CardKind;
  verb: string;
  coords: CellCoords;
  locale: 'en';
  site: { origin: string; name: string };
  header: string;
  reason_label?: string;
  sentence: string;
  facts: CardFactV2[];
  banners: string[];
  friction: FrictionTier;
  answers: { id: 'no' | 'partly' | 'yes'; label: string }[];
  /** typed tier: which value the human types (drawn from the card) and the fixed prompt. */
  typed?: { path: string; mode: 'number' | 'last4'; prompt: string };
  partial: PartialSlotV2[];
  rendered_digest: string;
}

// ---- text helpers -----------------------------------------------------------------------------------------------

/** Strip control characters, collapse whitespace, cap length. For the principal's own words and the site's name. */
export function cleanText(s: string, max: number): string {
  // eslint-disable-next-line no-control-regex
  const t = s.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

/** The last four letters/digits of a string (all a card ever shows of a string the outcome space does not name). */
export function last4(s: string): string {
  return s.replace(/[^A-Za-z0-9]/g, '').slice(-4).toUpperCase();
}

/** Thousands grouping with commas, independent of the runtime's locale data (cards must render identically anywhere). */
function group(n: number): string {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

const CURRENCY_SYMBOL: Readonly<Record<string, string>> = { USD: '$', EUR: '€', GBP: '£', JPY: '¥' };

export function formatNumber(x: number, unit: Unit | undefined): string {
  if (unit?.kind === 'money') {
    const e = Math.max(0, Math.min(6, Math.floor(unit.exponent)));
    const neg = x < 0;
    const a = Math.abs(Math.trunc(x));
    const div = 10 ** e;
    const whole = group(Math.floor(a / div));
    const frac = e > 0 ? `.${String(a % div).padStart(e, '0')}` : '';
    const sym = CURRENCY_SYMBOL[unit.currency] ?? `${unit.currency} `;
    return `${neg ? '-' : ''}${sym}${whole}${frac}`;
  }
  return `${x < 0 ? '-' : ''}${group(Math.abs(Math.trunc(x)))}`;
}

function dimLabel(path: string): string {
  let m = /^env\.acc\.([A-Za-z0-9_.-]+)\.post$/.exec(path);
  if (m) return `${m[1]!.replace(/[_.]/g, ' ')} (running total for this task)`;
  m = /^env\.world\.([A-Za-z0-9_.-]+)$/.exec(path);
  if (m) return `${m[1]!.replace(/[_.]/g, ' ')} (from a signed fact)`;
  m = /^env\.mon\.([A-Za-z0-9_.-]+)\.state$/.exec(path);
  if (m) return `state of ${m[1]!.replace(/[_.]/g, ' ')}`;
  return labelOf(path);
}

const isProvPath = (p: string) => p.startsWith('env.prov.');

function numFact(d: Extract<Dim, { kind: 'num' }>, ids: number[], unit: Unit | undefined, actionValue: unknown): string {
  const cells = numCells(d);
  const lo = cells[ids[0]!]!.lo;
  const hi = cells[ids[ids.length - 1]!]!.hi;
  let range: string;
  if (lo === hi) range = `exactly ${formatNumber(lo, unit)}`;
  else if (lo === d.lo && hi === d.hi) range = 'any value';
  else if (hi === d.hi) range = `${formatNumber(lo, unit)} or more`;
  else if (lo === d.lo) range = `up to ${formatNumber(hi, unit)}`;
  else range = `${formatNumber(lo, unit)} – ${formatNumber(hi, unit)}`;
  const ex = typeof actionValue === 'number' && Number.isFinite(actionValue) ? ` (this action: ${formatNumber(actionValue, unit)})` : '';
  return range + ex;
}

function catValueText(d: Extract<Dim, { kind: 'cat' }>, i: number): string {
  const v = d.values[i]!;
  if (v.kind === 'exact') return `"${cleanText(v.value, 64)}"`;
  if (v.kind === 'prefix') return `anything starting with "${cleanText(v.value, 64)}"`;
  return 'a value not named in your request';
}

function catFact(d: Extract<Dim, { kind: 'cat' }>, ids: number[], actionValue: unknown): string {
  const parts = ids.map((i) => catValueText(d, i));
  const set = parts.length === 1 ? parts[0]! : `${parts.slice(0, -1).join(', ')} or ${parts[parts.length - 1]!}`;
  if (typeof actionValue !== 'string') return set;
  const named = d.values.some((v) => v.kind === 'exact' && v.value === actionValue);
  return `${set} (this action: ${named ? `"${cleanText(actionValue, 64)}"` : `a value ending in "${last4(actionValue)}"`})`;
}

function bannerFor(path: string, levels: string[]): string | null {
  const w = worstProvenance(levels);
  const label = dimLabel(path);
  if (w === 'web') return `This ${label} was suggested by content on a web page, not by you.`;
  if (w === 'tool') return `This ${label} came from a tool result, not from you.`;
  if (w === 'agent') return `This ${label} was chosen by your agent, not taken from your request or from the site.`;
  return null;
}

/** Labels of a provenance coordinate: a level, or a group "tool|web|agent". Anything else is `agent` (fail closed). */
function provLevels(d: Extract<Dim, { kind: 'cat' }>, ids: number[]): string[] {
  return ids.flatMap((i) => catLabel(d, i).split(/[|,]/));
}

// ---- render -------------------------------------------------------------------------------------------------------

export type RenderResult = { ok: true; card: TrustedCard } | { ok: false; reason: string };

function typedTarget(vs: VerbSpace, action: ActionValues | undefined, units: Readonly<Record<string, Unit>> | undefined): TrustedCard['typed'] {
  if (!action) return undefined;
  const dims = vs.dims.map((d, k) => ({ d, k })).filter(({ d }) => !isProvPath(d.path));
  const nums = dims.filter(({ d }) => d.kind === 'num' && typeof action.values[d.path] === 'number');
  const money = nums.find(({ d }) => units?.[d.path]?.kind === 'money');
  const pick = money ?? nums[0];
  if (pick) return { path: pick.d.path, mode: 'number', prompt: `To allow it, type the ${dimLabel(pick.d.path)} of this action shown above.` };
  const cat = dims.find(({ d }) => d.kind === 'cat' && typeof action.values[d.path] === 'string' && last4(String(action.values[d.path])).length === 4);
  if (cat) return { path: cat.d.path, mode: 'last4', prompt: `To allow it, type the last 4 letters or digits of the ${dimLabel(cat.d.path)}.` };
  return undefined;
}

const ANSWERS: Record<FrictionTier, TrustedCard['answers']> = {
  tap: [{ id: 'no', label: 'No' }, { id: 'partly', label: 'Partly…' }, { id: 'yes', label: 'Yes' }],
  hold: [{ id: 'no', label: 'No' }, { id: 'partly', label: 'Partly…' }, { id: 'yes', label: 'Press and hold to allow' }],
  typed: [{ id: 'no', label: 'No' }, { id: 'partly', label: 'Partly…' }, { id: 'yes', label: 'Yes, type the value to confirm' }],
  device: [{ id: 'no', label: 'No' }, { id: 'partly', label: 'Partly…' }, { id: 'yes', label: 'Yes, confirm with your security key' }],
};

const REV_TEXT: Record<Reversibility, string> = {
  reversible: 'that can be undone',
  rate_limited: 'that is rate-limited',
  irreversible: 'that cannot be undone',
};

export function renderCard(input: CardInput): RenderResult {
  if ((input.locale ?? 'en') !== 'en') return { ok: false, reason: `unsupported locale ${String(input.locale)}` };
  if (input.kind === 'clarification' && input.reason === undefined) return { ok: false, reason: 'a clarification card needs a reason' };
  if (input.reason !== undefined && !(CLARIFY_REASONS as readonly string[]).includes(input.reason)) return { ok: false, reason: 'unknown clarification reason' };
  const r = resolveCoords(input.omega, input.verb, input.coords);
  if (!r.ok) return r;
  const { vs, box } = r;
  if (input.action && input.action.verb !== input.verb) return { ok: false, reason: 'the action is for another verb' };
  const catalog = input.catalog ?? DEFAULT_CATALOG;
  const siteName = cleanText(input.site.name, 64) || cleanText(input.site.origin, 64);
  const said = input.statementText !== undefined ? cleanText(input.statementText, 280) : '';
  const header =
    input.kind === 'clarification'
      ? said ? `Your agent needs a decision for your request "${said}"` : 'Your agent needs a decision'
      : said ? `${siteName} asks on behalf of your request "${said}"` : `${siteName} asks for your confirmation`;
  const spec = catalog.get(input.verb);
  const what = spec ? spec.description.replace(/\.$/, '').replace(/^./, (c) => c.toLowerCase()) : `the action "${cleanText(input.verb, 64)}" on ${siteName}`;
  const rev = input.reversibility ?? vs.reversibility;
  const sentence = `Allow ${what}, ${REV_TEXT[rev]}, with:`;
  const facts: CardFactV2[] = [];
  const banners: string[] = [];
  const partial: PartialSlotV2[] = [];
  vs.dims.forEach((d, k) => {
    const ids = box[k]!;
    const key = d.path;
    if (isProvPath(d.path)) {
      if (d.kind !== 'cat') return;
      const b = bannerFor(d.path.slice('env.prov.'.length), provLevels(d, ids));
      if (b) banners.push(b);
      return;
    }
    const av = input.action?.values[d.path];
    if (d.kind === 'num') {
      facts.push({ key, label: dimLabel(d.path), text: numFact(d, ids, input.units?.[d.path], av) });
      const cells = numCells(d);
      partial.push({ path: d.path, kind: 'num', lo: cells[ids[0]!]!.lo, hi: cells[ids[ids.length - 1]!]!.hi });
    } else {
      facts.push({ key, label: dimLabel(d.path), text: catFact(d, ids, av) });
      const options = ids.map((i) => d.values[i]!).filter((v) => v.kind === 'exact').map((v) => v.value);
      if (options.length > 1) partial.push({ path: d.path, kind: 'cat', options });
    }
  });
  const typed = frictionRank(input.friction) >= frictionRank('typed') ? typedTarget(vs, input.action, input.units) : undefined;
  const body = {
    v: 2 as const,
    kind: input.kind,
    verb: input.verb,
    coords: JSON.parse(JSON.stringify(input.coords)) as CellCoords,
    locale: 'en' as const,
    site: { origin: cleanText(input.site.origin, 256), name: siteName },
    header,
    ...(input.reason !== undefined ? { reason_label: REASON_LABELS[input.reason] } : {}),
    sentence,
    facts,
    banners,
    friction: input.friction,
    answers: ANSWERS[input.friction],
    ...(typed ? { typed } : {}),
    partial,
  };
  return { ok: true, card: { ...body, rendered_digest: cardDigest(body) } };
}

/** The content address of a card body (everything but `rendered_digest`). */
export function cardDigest(body: Omit<TrustedCard, 'rendered_digest'>): string {
  return hashCanonical({ d: CARD_DOMAIN, c: JSON.parse(JSON.stringify(body)) as unknown });
}

/** Recompute a card's digest and compare: an auditor's check that the stored card is the one that was hashed. */
export function cardDigestMatches(card: TrustedCard): boolean {
  const { rendered_digest, ...body } = card;
  return cardDigest(body) === rendered_digest;
}

/** The plain text of a card, line by line (what a screen reader or a text channel shows). */
export function cardText(card: TrustedCard): string {
  return [
    card.header,
    ...(card.reason_label ? [card.reason_label] : []),
    card.sentence,
    ...card.facts.map((f) => `- ${f.label}: ${f.text}`),
    ...card.banners,
    ...(card.typed ? [card.typed.prompt] : []),
    card.answers.map((a) => `[${a.label}]`).join(' '),
  ].join('\n');
}

// ---- responses ----------------------------------------------------------------------------------------------------

/** The evidence a "yes" (or a "Partly…", which is a yes for part of the cell) carries for its friction tier. */
export interface TierEvidence {
  /** hold tier: measured press-and-hold dwell (ms). */
  holdMs?: number;
  /** typed tier: what the human typed. */
  typed?: string;
  /** device tier: the WebAuthn assertion (base64url members). */
  webauthn?: WebAuthnEvidence;
}

export type CardResponse = { answer: 'no' } | ({ answer: 'yes' } & TierEvidence) | ({ answer: 'partly'; partial: PartialSpec } & TierEvidence);

/** Validate a "Partly…" answer against the card: a structured restriction of the shown ranges and values only. */
export function partialError(card: TrustedCard, p: PartialSpec): string | null {
  const slot = card.partial.find((s) => s.path === p.path);
  if (!slot) return `the card has no field ${p.path}`;
  if (slot.kind === 'num') {
    const inRange = (x: number) => Number.isInteger(x) && x >= slot.lo && x <= slot.hi;
    if ('upTo' in p) return inRange(p.upTo) && p.upTo < slot.hi ? null : `upTo must be an integer in [${slot.lo}, ${slot.hi - 1}]`;
    if ('from' in p) return inRange(p.from) && p.from > slot.lo ? null : `from must be an integer in [${slot.lo + 1}, ${slot.hi}]`;
    if ('except' in p) return p.except.length > 0 && p.except.every(inRange) ? null : `except values must be integers in [${slot.lo}, ${slot.hi}]`;
    return 'a numeric partly answer needs upTo, from or except';
  }
  if (!('notFor' in p)) return 'a categorical partly answer needs notFor';
  const vals = [...new Set(p.notFor)];
  if (vals.length === 0 || !vals.every((v) => slot.options.includes(v))) return 'notFor must name values shown on the card';
  if (vals.length === slot.options.length) return 'excluding every value is a "No"';
  return null;
}

/** Normalize what the human typed for comparison with the action value (digits for numbers, minor units for money). */
export function normalizeTyped(input: string, mode: 'number' | 'last4', unit: Unit | undefined): string | null {
  if (mode === 'last4') {
    const t = input.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    return t.length === 4 ? t : null;
  }
  const t = input.replace(/[\s,$€£¥]/g, '').replace(/^[A-Z]{3}/i, '');
  const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(t);
  if (!m) return null;
  const e = unit?.kind === 'money' ? Math.max(0, Math.min(6, Math.floor(unit.exponent))) : 0;
  const frac = m[3] ?? '';
  if (frac.length > e) return null;
  const minor = BigInt(m[2]!) * 10n ** BigInt(e) + (frac ? BigInt(frac.padEnd(e, '0')) : 0n);
  return `${m[1] === '-' && minor !== 0n ? '-' : ''}${minor.toString()}`;
}

/** The normalized value the human must type for this card and action (what a site or auditor recomputes). */
export function expectedTyped(card: TrustedCard, action: ActionValues): string | null {
  if (!card.typed) return null;
  const v = action.values[card.typed.path];
  if (card.typed.mode === 'last4') return typeof v === 'string' && last4(v).length === 4 ? last4(v) : null;
  return typeof v === 'number' && Number.isSafeInteger(v) ? String(v) : null;
}
