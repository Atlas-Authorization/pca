/**
 * Reputation from verifiable records: disputes are derived ONLY from guardian-signed settlement records
 * (open / release / slash). A record whose signature does not verify is counted in `rejected`, never as a dispute.
 */
import { type SettlementRecord, settlementRecordDigest, verifySettlement } from './bond-settlement';
import type { PqPinPolicy } from './pq';
import type { DisputeRecord } from './reputation';

export function disputesFromSettlements(
  records: readonly SettlementRecord[],
  guardianPublicKey: string,
  /** Maps a bond/claim handle to the subject it was posted for; undefined means unknown, and the record is rejected. */
  subjectOf: (claimId: string) => string | undefined,
  pin?: PqPinPolicy,
): { disputes: DisputeRecord[]; rejected: number } {
  const disputes: DisputeRecord[] = [];
  let rejected = 0;
  for (const r of records) {
    const subject = r && typeof r.claimId === 'string' ? subjectOf(r.claimId) : undefined;
    if (subject === undefined || !verifySettlement(r, guardianPublicKey, pin)) { rejected++; continue; }
    if (r.action === 'open') continue; // an open bond is not an outcome
    disputes.push({ id: settlementRecordDigest(r), subject, slashed: r.action === 'slash', at: r.at, amount: r.amount });
  }
  return { disputes, rejected };
}
