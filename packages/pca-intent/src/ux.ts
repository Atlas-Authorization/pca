import { DEFAULT_CATALOG, hashCanonical, type Catalog } from '@atlasauth/pca';
import type { Question } from './learner';
import { numCells, repValue, type Dim, type Omega } from './omega';
import type { AdaptiveAnswer, PartialAnswer } from './refine';
import { labelOf, renderQuestion } from './render';

/**
 * QUESTION UX COMPONENTS (for the M4 human study; spec §10). A question card is a deterministic, structured form of a
 * cell question: the rendered sentence, one fact line per dimension (the range asked about and the boundary
 * example), the verb's reversibility, and the three answers. "Partly" is offered per dimension in a typed shape
 * (numeric: "yes up to x" / "yes from x" / "except x"; categorical: "not for these values"; and "not for these
 * values of a field the question did not mention", which adds a dimension). `parseCardAnswer` turns the UI input
 * into the learner's answer (`AdaptiveAnswer`), rejecting anything that does not fit the card.
 */

export interface CardFact {
  path: string;
  label: string;
  text: string;
}

export type PartialSlot = { path: string; kind: 'num'; lo: number; hi: number } | { path: string; kind: 'cat'; options: string[] };

export interface QuestionCard {
  v: 1;
  verb: string;
  cell: number[];
  sentence: string;
  facts: CardFact[];
  reversibility: string;
  answers: ['yes', 'no', 'partly'];
  partial: PartialSlot[];
  /** Content address of the card (the study logs which exact card a participant saw). */
  digest: string;
}

function factOf(d: Dim, i: number): CardFact {
  const label = labelOf(d.path);
  if (d.kind === 'num') {
    const c = numCells(d)[i]!;
    return { path: d.path, label, text: c.lo === c.hi ? `exactly ${c.lo}` : `any value from ${c.lo} to ${c.hi} (for example ${String(repValue(d, i))})` };
  }
  const v = d.values[i]!;
  return { path: d.path, label, text: v.kind === 'exact' ? `"${v.value}"` : v.kind === 'prefix' ? `anything under "${v.value}" not named elsewhere` : 'any value not named anywhere in the grant or your request' };
}

export function questionCard(omega: Omega, q: Pick<Question, 'verb' | 'cell'>, catalog: Catalog = DEFAULT_CATALOG): QuestionCard {
  const vs = omega.verbs.find((v) => v.verb === q.verb);
  if (!vs) throw new Error(`questionCard: no verb ${q.verb}`);
  const facts = vs.dims.map((d, k) => factOf(d, q.cell[k]!));
  const partial: PartialSlot[] = vs.dims.map((d, k) => {
    if (d.kind === 'num') {
      const c = numCells(d)[q.cell[k]!]!;
      return { path: d.path, kind: 'num' as const, lo: c.lo, hi: c.hi };
    }
    return { path: d.path, kind: 'cat' as const, options: d.values.filter((v) => v.kind === 'exact').map((v) => v.value) };
  });
  const body = { v: 1 as const, verb: q.verb, cell: [...q.cell], sentence: renderQuestion(vs, q.cell, catalog), facts, reversibility: vs.reversibility, answers: ['yes', 'no', 'partly'] as ['yes', 'no', 'partly'], partial };
  return { ...body, digest: hashCanonical({ d: 'atlas-pca/intent-card/v1', c: JSON.parse(JSON.stringify(body)) as unknown }) };
}

export type CardInput =
  | { answer: 'yes' | 'no' }
  | { answer: 'partly'; path: string; upTo: number }
  | { answer: 'partly'; path: string; from: number }
  | { answer: 'partly'; path: string; except: number[] }
  | { answer: 'partly'; path: string; notFor: string[] }
  /** A field the card did not show: "yes, except when <field> is one of …" (adds a categorical dimension). */
  | { answer: 'partly'; newField: string; notFor: string[] };

export type ParsedCardAnswer = { ok: true; answer: AdaptiveAnswer } | { ok: false; error: string };

const FIELD_RE = /^(action\.params\.[a-z_][a-z0-9_]*|action\.resource)$/;

export function parseCardAnswer(card: QuestionCard, input: CardInput): ParsedCardAnswer {
  if (input.answer !== 'partly') return { ok: true, answer: input.answer === 'yes' ? 1 : 0 };
  if ('newField' in input) {
    if (!FIELD_RE.test(input.newField)) return { ok: false, error: `unknown field ${input.newField}` };
    if (card.partial.some((s) => s.path === input.newField)) return { ok: false, error: `${input.newField} is already on the card; answer partly for it directly` };
    const vals = [...new Set(input.notFor.filter((x) => typeof x === 'string' && x.length > 0))];
    if (vals.length === 0) return { ok: false, error: 'name at least one value' };
    const a: PartialAnswer = {
      kind: 'partial',
      path: input.newField,
      newDim: { kind: 'cat', path: input.newField, values: [...vals.map((value) => ({ kind: 'exact' as const, value })), { kind: 'other', value: '⊥' }] },
      parts: [{ values: vals, y: 0 }, { other: true, y: 1 }],
    };
    return { ok: true, answer: a };
  }
  const slot = card.partial.find((s) => s.path === input.path);
  if (!slot) return { ok: false, error: `the card has no field ${input.path}` };
  if (slot.kind === 'num') {
    const inRange = (x: number) => Number.isInteger(x) && x >= slot.lo && x <= slot.hi;
    if ('upTo' in input) {
      if (!inRange(input.upTo) || input.upTo === slot.hi) return { ok: false, error: `upTo must be an integer in [${slot.lo}, ${slot.hi - 1}]` };
      return { ok: true, answer: { kind: 'partial', path: slot.path, cuts: [input.upTo], parts: [{ lo: slot.lo, hi: input.upTo, y: 1 }, { lo: input.upTo + 1, hi: slot.hi, y: 0 }] } };
    }
    if ('from' in input) {
      if (!inRange(input.from) || input.from === slot.lo) return { ok: false, error: `from must be an integer in [${slot.lo + 1}, ${slot.hi}]` };
      return { ok: true, answer: { kind: 'partial', path: slot.path, cuts: [input.from], parts: [{ lo: slot.lo, hi: input.from - 1, y: 0 }, { lo: input.from, hi: slot.hi, y: 1 }] } };
    }
    if ('except' in input) {
      const ex = [...new Set(input.except)].sort((a, b) => a - b);
      if (ex.length === 0 || !ex.every(inRange)) return { ok: false, error: `except values must be integers in [${slot.lo}, ${slot.hi}]` };
      // A cut at x makes {x} its own cell; the "no" parts come first so they win over the covering "yes".
      return { ok: true, answer: { kind: 'partial', path: slot.path, cuts: ex, parts: [...ex.map((x) => ({ lo: x, hi: x, y: 0 as const })), { lo: slot.lo, hi: slot.hi, y: 1 }] } };
    }
    return { ok: false, error: 'a numeric partly answer needs upTo, from or except' };
  }
  if (!('notFor' in input)) return { ok: false, error: 'a categorical partly answer needs notFor' };
  const vals = [...new Set(input.notFor.filter((x) => typeof x === 'string' && x.length > 0))];
  if (vals.length === 0) return { ok: false, error: 'name at least one value' };
  return { ok: true, answer: { kind: 'partial', path: slot.path, values: vals, parts: [{ values: vals, y: 0 }, { other: true, y: 1 }] } };
}
