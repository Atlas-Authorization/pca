/**
 * TEST-ONLY builder for AMD SEV-SNP `ATTESTATION_REPORT` byte buffers in the genuine report layout
 * (the inverse of `parseSevSnpReport`). Production code only ever PARSES reports emitted by real
 * hardware; tests use this to craft reports with known fields (optionally signed with a test key).
 * Excluded from the published build. Fields default to zero; byte fields are truncated to size.
 */
const OFF = {
  VERSION: 0x000,
  GUEST_SVN: 0x004,
  POLICY: 0x008,
  FAMILY_ID: 0x010,
  IMAGE_ID: 0x020,
  VMPL: 0x030,
  SIGNATURE_ALGO: 0x034,
  CURRENT_TCB: 0x038,
  PLATFORM_INFO: 0x040,
  REPORT_DATA: 0x050,
  MEASUREMENT: 0x090,
  HOST_DATA: 0x0c0,
  ID_KEY_DIGEST: 0x0e0,
  AUTHOR_KEY_DIGEST: 0x110,
  REPORT_ID: 0x140,
  REPORT_ID_MA: 0x160,
  REPORTED_TCB: 0x180,
  CHIP_ID: 0x1a0,
  COMMITTED_TCB: 0x1e0,
  LAUNCH_TCB: 0x1f0,
  SIG_R: 0x2a0,
  SIG_S: 0x2e8,
  REPORT_LEN: 0x4a0,
} as const;

export interface SevSnpReportFields {
  version: number;
  guest_svn: number;
  policy: bigint;
  family_id: Uint8Array;
  image_id: Uint8Array;
  vmpl: number;
  signature_algo: number;
  current_tcb: bigint;
  platform_info: bigint;
  report_data: Uint8Array;
  measurement: Uint8Array;
  host_data: Uint8Array;
  id_key_digest: Uint8Array;
  author_key_digest: Uint8Array;
  report_id: Uint8Array;
  report_id_ma: Uint8Array;
  reported_tcb: bigint;
  chip_id: Uint8Array;
  committed_tcb: bigint;
  launch_tcb: bigint;
  signature: { r: Uint8Array; s: Uint8Array };
}

export function serializeSevSnpReport(fields: Partial<SevSnpReportFields>): Uint8Array {
  const out = new Uint8Array(OFF.REPORT_LEN);
  const dv = new DataView(out.buffer);
  const put = (off: number, len: number, src?: Uint8Array) => {
    if (!src) return;
    out.set(src.subarray(0, len), off);
  };
  dv.setUint32(OFF.VERSION, fields.version ?? 2, true);
  dv.setUint32(OFF.GUEST_SVN, fields.guest_svn ?? 0, true);
  dv.setBigUint64(OFF.POLICY, fields.policy ?? 0n, true);
  put(OFF.FAMILY_ID, 16, fields.family_id);
  put(OFF.IMAGE_ID, 16, fields.image_id);
  dv.setUint32(OFF.VMPL, fields.vmpl ?? 0, true);
  dv.setUint32(OFF.SIGNATURE_ALGO, fields.signature_algo ?? 1, true);
  dv.setBigUint64(OFF.CURRENT_TCB, fields.current_tcb ?? 0n, true);
  dv.setBigUint64(OFF.PLATFORM_INFO, fields.platform_info ?? 0n, true);
  put(OFF.REPORT_DATA, 64, fields.report_data);
  put(OFF.MEASUREMENT, 48, fields.measurement);
  put(OFF.HOST_DATA, 32, fields.host_data);
  put(OFF.ID_KEY_DIGEST, 48, fields.id_key_digest);
  put(OFF.AUTHOR_KEY_DIGEST, 48, fields.author_key_digest);
  put(OFF.REPORT_ID, 32, fields.report_id);
  put(OFF.REPORT_ID_MA, 32, fields.report_id_ma);
  dv.setBigUint64(OFF.REPORTED_TCB, fields.reported_tcb ?? 0n, true);
  put(OFF.CHIP_ID, 64, fields.chip_id);
  dv.setBigUint64(OFF.COMMITTED_TCB, fields.committed_tcb ?? 0n, true);
  dv.setBigUint64(OFF.LAUNCH_TCB, fields.launch_tcb ?? 0n, true);
  if (fields.signature) {
    put(OFF.SIG_R, 72, fields.signature.r);
    put(OFF.SIG_S, 72, fields.signature.s);
  }
  return out;
}
