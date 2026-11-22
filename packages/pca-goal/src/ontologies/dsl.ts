import type { Op, ResPart, ResSel, Value } from '../ir';
import type { TCond, TemplateBound, TemplateGrant, TemplateProhibit } from '../ontology';

export const T: TCond = { k: 'true' };
export const cmp = (op: Op, param: string, slot: string): TCond => ({ k: 'cmp', op, l: { k: 'param', path: param }, r: { k: 'slot', slot } });
export const cmpEnum = (op: Op, param: string, v: string): TCond => ({ k: 'cmp', op, l: { k: 'param', path: param }, r: { k: 'lit', v: { k: 's', s: v } } });
export const inEnum = (param: string, vs: string[]): TCond => ({ k: 'cmp', op: 'in', l: { k: 'param', path: param }, r: { k: 'lit', v: { k: 'set', items: vs.map((s): Value => ({ k: 's', s })) } } });
export const and = (...args: TCond[]): TCond => args.reduce((a, b) => ({ k: 'and', a, b }));
export const exact = (slot: string): ResPart => ({ k: 'exact', id: '$' + slot });
export const related = (rel: string, slot: string): ResPart => ({ k: 'related', rel, anchor: '$' + slot });
/** Resource conjunction: the IR's flat `all_of` (at least two parts). */
export const both = (...parts: ResPart[]): ResSel => ({ k: 'all_of', parts });
export const grant = (gid: string, verb: string, res: ResSel, cond: TCond = T): TemplateGrant => ({ gid, verb, res, cond });
export const ban = (...verbs: string[]): TemplateProhibit[] => verbs.map((v) => ({ pid: `no-${v}`, target: { k: 'verb', verb: v }, res: { k: 'any', reason: 'blanket' }, cond: T }));
export const countCap = (bid: string, over: string[] | 'all', n: number, capSlot?: string): TemplateBound => ({ bid, agg: 'count', over, cap: { u: { k: 'count' }, n }, onExceed: 'deny', ...(capSlot ? { cap_slot: capSlot } : {}) });
export const sumCap = (bid: string, over: string[] | 'all', param: string, ccy: string, capSlot: string): TemplateBound => ({ bid, agg: 'sum', over, param, cap: { u: { k: 'money', ccy }, n: 0 }, onExceed: 'deny', cap_slot: capSlot });
export const CCYS = ['USD', 'EUR', 'GBP', 'JPY'];
export const UNITS_MONEY = { USD: { kind: 'money', exponent: 2 }, EUR: { kind: 'money', exponent: 2 }, GBP: { kind: 'money', exponent: 2 }, JPY: { kind: 'money', exponent: 0 } } as const;
