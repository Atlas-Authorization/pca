import { domainVerbs } from '@atlasauth/pca-actions';
import type { IntentOntology } from '../ontology';
import { and, ban, cmp, cmpEnum, countCap, exact, grant } from './dsl';
import { UNITS_MONEY } from './dsl';

const AIRPORTS = ['SFO', 'LAX', 'JFK', 'LHR', 'CDG', 'NRT', 'AUS', 'SEA'];
const VERBS = domainVerbs('calendar_travel');
export const travel: IntentOntology = {
  id: 'atlas.travel', version: 1, domain: 'calendar_travel',
  types: [{ id: 'trip', id_prefix: 'trip_' }, { id: 'booking', id_prefix: 'bk_' }, { id: 'traveler', id_prefix: 'trv_' }],
  units: { ...UNITS_MONEY, count: { kind: 'count' }, instant: { kind: 'instant' } },
  relations: [{ id: 'bookings_of', from: 'trip', to: 'booking' }],
  // derived from the action definitions (@atlasauth/pca-actions): the effect class, parameter kinds and aliases are not written here
  verbs: VERBS.verbs,
  aliases: VERBS.aliases,
  templates: [
    {
      id: 'book_flight', title: 'Book one flight to a destination within a price', phrases: ['book a flight', 'book flight', 'book the flight'],
      slots: [
        { name: 'trip', kind: 'id', of: 'trip', mandatory: true },
        { name: 'destination', kind: 'enum', values: AIRPORTS, mandatory: true },
        { name: 'max_price', kind: 'money', ccy: 'USD', mandatory: true, max: 2_000_000 },
      ],
      grants: [
        grant('search', 'search', exact('trip')),
        grant('hold', 'hold', exact('trip'), and(cmp('lte', 'price', 'max_price'), cmp('eq', 'destination', 'destination'))),
        grant('book', 'book', exact('trip'), and(cmp('lte', 'price', 'max_price'), cmp('eq', 'destination', 'destination'))),
      ],
      prohibits: ban('cancel_booking'), bounds: [countCap('one-booking', ['book'], 1)],
      example: { trip: 'trip_1', destination: 'SFO', max_price: { ccy: 'USD', minor: 50000 } },
    },
    {
      id: 'search_only', title: 'Search flights only', phrases: ['search for flights', 'look up flights', 'just search', 'only search'],
      slots: [{ name: 'trip', kind: 'id', of: 'trip', mandatory: true }],
      grants: [grant('search', 'search', exact('trip'))],
      prohibits: ban('hold', 'book', 'cancel_booking'), bounds: [],
      example: { trip: 'trip_1' },
    },
    {
      id: 'hold_only', title: 'Hold (not book) within a price', phrases: ['put a hold', 'hold a flight', 'hold the flight', 'only hold'],
      slots: [{ name: 'trip', kind: 'id', of: 'trip', mandatory: true }, { name: 'max_price', kind: 'money', ccy: 'USD', mandatory: true, max: 2_000_000 }],
      grants: [grant('search', 'search', exact('trip')), grant('hold', 'hold', exact('trip'), cmp('lte', 'price', 'max_price'))],
      prohibits: ban('book', 'cancel_booking'), bounds: [countCap('holds', ['hold'], 3)],
      example: { trip: 'trip_1', max_price: { ccy: 'USD', minor: 60000 } },
    },
    {
      id: 'cancel_one_booking', title: 'Cancel one booking', phrases: ['cancel my booking', 'cancel booking', 'cancel the booking'],
      slots: [{ name: 'booking', kind: 'id', of: 'booking', mandatory: true }],
      grants: [grant('cancel', 'cancel_booking', exact('booking'))],
      prohibits: ban('book', 'hold'), bounds: [countCap('once', 'all', 1)],
      example: { booking: 'bk_1' },
    },
  ],
};
void cmpEnum;
