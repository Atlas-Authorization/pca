// The hand-written domain ontologies' verb tables and alias maps as they were before they were derived from the ActionDefs
// (recorded once from the pre-derivation source). The derived tables must equal them: same ids, same effect classes, same
// resource types, same parameter kinds, same aliases. Enum and currency lists are compared as sets (the derivation sorts them).
import { describe, expect, it } from 'vitest';
import { ALL_ONTOLOGIES, checkOntology } from '../src';

const OLD: Record<string, { verbs: unknown[]; aliases: Record<string, string> }> = {
  "payments": {"verbs":[{"id":"read_charge","effect":"read","resource_type":"charge","params":{}},{"id":"refund","effect":"irreversible","resource_type":"charge","params":{"amount":{"kind":"money","ccys":["USD","EUR","GBP","JPY"]}}},{"id":"charge_customer","effect":"irreversible","resource_type":"customer","params":{"amount":{"kind":"money","ccys":["USD","EUR","GBP","JPY"]}}},{"id":"transfer","effect":"irreversible","resource_type":"account","params":{"amount":{"kind":"money","ccys":["USD","EUR","GBP","JPY"]}}},{"id":"payout","effect":"irreversible","resource_type":"account","params":{"amount":{"kind":"money","ccys":["USD","EUR","GBP","JPY"]}}},{"id":"cancel_subscription","effect":"reversible","resource_type":"subscription","params":{}}],"aliases":{"issue_refund":"refund","reimburse":"refund","refund_charge":"refund","bill":"charge_customer","cancel_plan":"cancel_subscription","send_money":"transfer","pay_out":"payout","view_charge":"read_charge"}},
  "email": {"verbs":[{"id":"read_thread","effect":"read","resource_type":"thread","params":{}},{"id":"label","effect":"reversible","resource_type":"thread","params":{"label":{"kind":"enum","values":["important","follow_up","receipts","newsletters","later"]}}},{"id":"archive","effect":"reversible","resource_type":"thread","params":{}},{"id":"delete","effect":"irreversible","resource_type":"thread","params":{}},{"id":"send","effect":"external_send","resource_type":"thread","params":{"to_domain":{"kind":"text"}}},{"id":"forward","effect":"external_send","resource_type":"thread","params":{"to_domain":{"kind":"text"}}}],"aliases":{"trash":"delete","remove":"delete","reply":"send","respond":"send","file_away":"archive","tag":"label","open":"read_thread","read":"read_thread"}},
  "calendar_travel": {"verbs":[{"id":"search","effect":"read","resource_type":"trip","params":{"destination":{"kind":"enum","values":["SFO","LAX","JFK","LHR","CDG","NRT","AUS","SEA"]}}},{"id":"hold","effect":"reversible","resource_type":"trip","params":{"price":{"kind":"money","ccys":["USD","EUR","GBP","JPY"]},"destination":{"kind":"enum","values":["SFO","LAX","JFK","LHR","CDG","NRT","AUS","SEA"]}}},{"id":"book","effect":"irreversible","resource_type":"trip","params":{"price":{"kind":"money","ccys":["USD","EUR","GBP","JPY"]},"destination":{"kind":"enum","values":["SFO","LAX","JFK","LHR","CDG","NRT","AUS","SEA"]},"depart":{"kind":"instant"}}},{"id":"cancel_booking","effect":"irreversible","resource_type":"booking","params":{}}],"aliases":{"find_flights":"search","look_up":"search","reserve":"hold","purchase":"book","buy_ticket":"book","cancel_flight":"cancel_booking"}},
  "code_repos": {"verbs":[{"id":"read_repo","effect":"read","resource_type":"repo","params":{}},{"id":"create_branch","effect":"reversible","resource_type":"repo","params":{"branch":{"kind":"id","of":"ref"}}},{"id":"push","effect":"reversible","resource_type":"repo","params":{"branch":{"kind":"id","of":"ref"},"protected":{"kind":"enum","values":["yes","no"]}}},{"id":"merge","effect":"irreversible","resource_type":"repo","params":{"branch":{"kind":"id","of":"ref"},"protected":{"kind":"enum","values":["yes","no"]}}},{"id":"release","effect":"external_send","resource_type":"repo","params":{}},{"id":"delete_branch","effect":"irreversible","resource_type":"repo","params":{"branch":{"kind":"id","of":"ref"},"protected":{"kind":"enum","values":["yes","no"]}}}],"aliases":{"clone":"read_repo","fetch":"read_repo","commit_and_push":"push","publish":"release","ship":"release","remove_branch":"delete_branch","open_branch":"create_branch"}},
  "data_access": {"verbs":[{"id":"query","effect":"read","resource_type":"dataset","params":{"column_class":{"kind":"enum","values":["public","internal","pii"]},"rows":{"kind":"count"},"purpose":{"kind":"enum","values":["analytics","support","research","marketing"]}}},{"id":"export","effect":"external_send","resource_type":"dataset","params":{"column_class":{"kind":"enum","values":["public","internal","pii"]},"rows":{"kind":"count"},"purpose":{"kind":"enum","values":["analytics","support","research","marketing"]}}},{"id":"delete_dataset","effect":"irreversible","resource_type":"dataset","params":{}}],"aliases":{"select":"query","read_rows":"query","download":"export","dump":"export","drop":"delete_dataset","purge":"delete_dataset"}},
};

const norm = (x: unknown): unknown => JSON.parse(JSON.stringify(x, (_k, v) => (Array.isArray(v) && v.every((e) => typeof e === 'string') ? [...v].sort() : v)));

describe('the domain ontologies are derived from the action definitions', () => {
  for (const o of Object.values(ALL_ONTOLOGIES)) {
    it(`${o.domain}: verbs and aliases equal the recorded hand-written tables`, () => {
      expect(norm(o.verbs)).toEqual(norm(OLD[o.domain]!.verbs));
      expect(o.aliases).toEqual(OLD[o.domain]!.aliases);
    });
    it(`${o.domain}: the ontology is still well formed (templates compile against the derived verbs)`, () => {
      expect(checkOntology(o)).toEqual([]);
    });
  }
  it('every domain is covered', () => {
    expect(Object.values(ALL_ONTOLOGIES).map((o) => o.domain).sort()).toEqual(Object.keys(OLD).sort());
  });
});
