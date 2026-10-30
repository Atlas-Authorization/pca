// travel - search, booking, change and cancellation of flights, hotels, cars and rail, plus loyalty and traveller profiles.
// Hand written from the general shape of GDS/NDC-style and aggregator booking APIs; no vendor schema is carried.
import { P, def, handPack, type H } from '../lib/hand';

const KINDS: { ns: string; name: string; search: H['params'] }[] = [
  { ns: 'flights', name: 'flight', search: { origin: P.str(3), destination: P.str(3), depart: P.date(), return_date: P.opt(P.date()), adults: P.int(1, 9) } },
  { ns: 'hotels', name: 'hotel stay', search: { city: P.str(128), check_in: P.date(), check_out: P.date(), guests: P.int(1, 20) } },
  { ns: 'cars', name: 'car rental', search: { pickup: P.str(128), pickup_at: P.dt(), dropoff_at: P.dt() } },
  { ns: 'rail', name: 'rail ticket', search: { origin: P.str(128), destination: P.str(128), depart_at: P.dt(), passengers: P.int(1, 9) } },
];
const out: H[] = [];
for (const k of KINDS) {
  out.push(
    { verb: `${k.ns}.search`, title: `Search ${k.name} offers`, description: 'Finds priced offers. Nothing is held or charged.', effects: ['read'], res: [`${k.ns}.offer`, 'set'], params: { ...k.search, limit: P.limit(250) } },
    { verb: `${k.ns}.get_offer`, title: `Read a ${k.name} offer`, description: 'Current price and conditions of one offer.', effects: ['read'], res: [`${k.ns}.offer`, 'one'], params: { offer: P.id(`${k.ns}.offer`) } },
    { verb: `${k.ns}.hold`, title: `Hold a ${k.name}`, description: 'Reserves an offer for a short time without paying.', effects: ['create'], rev: 'rate_limited', res: [`${k.ns}.booking`, 'set'], params: { offer: P.id(`${k.ns}.offer`), traveller: P.str(140, { role: 'person.name', tags: ['pii'] }), contact_email: P.email() } },
    { verb: `${k.ns}.book`, title: `Book and pay for a ${k.name}`, description: 'Confirms the booking and charges the payment method; fares are usually non-refundable or carry change fees.', effects: ['pay', 'create'], rev: 'irreversible', idem: 'key', res: [`${k.ns}.booking`, 'set'], params: { offer: P.id(`${k.ns}.offer`), amount: P.money(100_000_00, 'currency'), currency: P.ccy(), traveller: P.str(140, { role: 'person.name', tags: ['pii'] }), contact_email: P.email(), payment_method: P.id('payments.method') } },
    { verb: `${k.ns}.get_booking`, title: `Read a ${k.name} booking`, description: 'Details of a booking, including traveller data.', effects: ['read'], traits: ['pca.pii_access'], res: [`${k.ns}.booking`, 'one'], params: { booking: P.id(`${k.ns}.booking`) } },
    { verb: `${k.ns}.list_bookings`, title: `List ${k.name} bookings`, description: 'Bookings of the account.', effects: ['read'], traits: ['pca.pii_access'], res: [`${k.ns}.booking`, 'set'], params: { since: P.opt(P.dt()), limit: P.limit(500) } },
    { verb: `${k.ns}.modify`, title: `Change a ${k.name} booking`, description: 'Changes dates or details; may cost a fee or fare difference.', effects: ['update', 'pay'], rev: 'irreversible', idem: 'key', res: [`${k.ns}.booking`, 'one'], params: { booking: P.id(`${k.ns}.booking`), amount: P.money(100_000_00, 'currency'), currency: P.ccy(), changes: P.obj() } },
    { verb: `${k.ns}.cancel`, title: `Cancel a ${k.name} booking`, description: 'Cancels the booking; refund depends on fare rules and may be zero.', effects: ['delete'], rev: 'irreversible', res: [`${k.ns}.booking`, 'one'], params: { booking: P.id(`${k.ns}.booking`) } },
    { verb: `${k.ns}.refund`, title: `Refund a ${k.name} booking`, description: 'Returns the refundable amount to the payment method.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: [`${k.ns}.booking`, 'one'], params: { booking: P.id(`${k.ns}.booking`), amount: P.money(100_000_00, 'currency'), currency: P.ccy() } },
    { verb: `${k.ns}.send_itinerary`, title: `Email a ${k.name} itinerary`, description: 'Sends the itinerary to an address.', effects: ['send'], rev: 'irreversible', res: [`${k.ns}.booking`, 'one'], params: { booking: P.id(`${k.ns}.booking`), to: P.email({ role: 'contact.email' }) } },
  );
}
out.push(
  { verb: 'flights.select_seat', title: 'Choose a seat', description: 'Assigns a seat, often for a fee.', effects: ['update', 'pay'], rev: 'irreversible', idem: 'key', res: ['flights.booking', 'one'], params: { booking: P.id('flights.booking'), seat: P.str(4), amount: P.money(10_000_00, 'currency'), currency: P.ccy() } },
  { verb: 'flights.add_baggage', title: 'Add baggage', description: 'Buys extra baggage.', effects: ['update', 'pay'], rev: 'irreversible', idem: 'key', res: ['flights.booking', 'one'], params: { booking: P.id('flights.booking'), pieces: P.int(1, 10), amount: P.money(10_000_00, 'currency'), currency: P.ccy() } },
  { verb: 'flights.check_in', title: 'Check in', description: 'Checks a traveller in and issues boarding passes.', effects: ['update'], rev: 'irreversible', res: ['flights.booking', 'one'], params: { booking: P.id('flights.booking') } },
  { verb: 'flights.flight_status', title: 'Read flight status', description: 'Live status of a flight.', effects: ['read'], res: ['flights.flight', 'one'], params: { flight: P.id('flights.flight', { max_len: 16 }), date: P.date() } },
  { verb: 'flights.price_alert_create', title: 'Create a fare alert', description: 'Watches a route and notifies on price drops.', effects: ['create'], rev: 'reversible', traits: ['pca.scheduled'], res: ['flights.alert', 'set'], params: { origin: P.str(3), destination: P.str(3), max_price: P.int(1, 100_000_00) } },
  { verb: 'hotels.get_rates', title: 'Read hotel room rates', description: 'Room types and cancellation terms for a property.', effects: ['read'], res: ['hotels.property', 'one'], params: { property: P.id('hotels.property'), check_in: P.date(), check_out: P.date() } },
  { verb: 'hotels.add_review', title: 'Post a hotel review', description: 'Publishes a public review.', effects: ['publish'], rev: 'irreversible', res: ['hotels.property', 'one'], params: { property: P.id('hotels.property'), text: P.pub(5000), rating: P.int(1, 10) } },
  { verb: 'cars.extend', title: 'Extend a car rental', description: 'Adds days to a rental, charging the rate.', effects: ['update', 'pay'], rev: 'irreversible', idem: 'key', res: ['cars.booking', 'one'], params: { booking: P.id('cars.booking'), days: P.int(1, 90), amount: P.money(100_000_00, 'currency'), currency: P.ccy() } },
  { verb: 'loyalty.get_balance', title: 'Read a loyalty balance', description: 'Points or miles balance.', effects: ['read'], traits: ['pca.pii_access'], res: ['loyalty.account', 'one'], params: { account: P.id('loyalty.account') } },
  { verb: 'loyalty.redeem', title: 'Redeem loyalty points', description: 'Spends points on an award; points are rarely restored in full.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['loyalty.account', 'one'], params: { account: P.id('loyalty.account'), points: P.int(1, 10_000_000, { role: 'money.amount', unit: { kind: 'money', ccy: 'PTS', exp: 0 }, provenance_min: 'tool' }), award: P.str(128) } },
  { verb: 'loyalty.transfer_points', title: 'Transfer loyalty points', description: 'Moves points to another member or programme.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['loyalty.account', 'one'], params: { account: P.id('loyalty.account'), to_account: P.payee(), points: P.int(1, 10_000_000, { role: 'money.amount', unit: { kind: 'money', ccy: 'PTS', exp: 0 }, provenance_min: 'tool' }) } },
  { verb: 'loyalty.update_profile', title: 'Update a loyalty profile', description: 'Changes member contact details.', effects: ['update'], rev: 'rate_limited', res: ['loyalty.account', 'one'], params: { account: P.id('loyalty.account'), email: P.opt(P.email()), phone: P.opt(P.phone()) } },
  { verb: 'traveller.get_profile', title: 'Read a traveller profile', description: 'Name, passport and preferences.', effects: ['read'], traits: ['pca.pii_access'], res: ['traveller.profile', 'one'], params: { profile: P.id('traveller.profile') } },
  { verb: 'traveller.update_profile', title: 'Update a traveller profile', description: 'Changes stored travel documents and preferences.', effects: ['update'], rev: 'rate_limited', res: ['traveller.profile', 'one'], params: { profile: P.id('traveller.profile'), passport_number: P.opt(P.str(32, { role: 'person.national_id', tags: ['pii'], provenance_min: 'tool' })), date_of_birth: P.opt(P.date({ role: 'person.dob', tags: ['pii'] })) } },
  { verb: 'traveller.delete_profile', title: 'Delete a traveller profile', description: 'Erases a stored profile.', effects: ['delete'], res: ['traveller.profile', 'one'], params: { profile: P.id('traveller.profile') } },
  { verb: 'visa.check_requirements', title: 'Check visa requirements', description: 'Entry rules for a nationality and destination.', effects: ['read'], res: ['visa.rule', 'set'], params: { nationality: P.str(2, { format: 'iso_country' }), destination: P.str(2, { format: 'iso_country' }) } },
  { verb: 'insurance.buy', title: 'Buy travel insurance', description: 'Purchases a policy.', effects: ['pay', 'sign'], rev: 'irreversible', idem: 'key', res: ['insurance.policy', 'set'], params: { booking: P.id('flights.booking'), amount: P.money(100_000_00, 'currency'), currency: P.ccy() } },
  { verb: 'expense.submit_report', title: 'Submit an expense report', description: 'Sends travel expenses for reimbursement approval.', effects: ['send'], rev: 'irreversible', res: ['expense.report', 'set'], params: { report: P.obj(), approver: P.email() } },
);

export default handPack({
  name: 'travel',
  licence_notes: 'Written in-house from the general shape of public travel booking APIs and fare-rule concepts; no vendor text or schema is carried.',
  config_file: __filename,
  sourceUri: 'in-repo:scripts/actions-packs/packs/travel.ts',
  defs: out.map(def),
});
