// Emits sdks/swift-pca/Sources/AtlasPCAVerify/ComplianceControls.swift (the control-mapping table, byte-identical to the reference)
// from the `constants` case of out/ref-compliance.json.gz.   node tools/pca-audit/oracles/compliance-swift-table.mjs
import fs from 'node:fs';
import zlib from 'node:zlib';
const root = new URL('../../../', import.meta.url).pathname;
const text = zlib.gunzipSync(fs.readFileSync(root + 'tools/pca-audit/oracles/out/ref-compliance.json.gz')).toString('utf8');
const c = text.split('\n').filter((l) => l.startsWith('{"fn":"constants"')).map((l) => JSON.parse(l.replace(/,$/, '')))[0].out;
const lit = (s) => '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
let o = `import Foundation

/// The control-mapping table of the compliance evidence report: each control, what it requires and the PCA evidence that addresses it.
/// Control ids are stable (a report item cites them).
extension PCACompliance {
    static let frameworks: [String] = [${c.COMPLIANCE_FRAMEWORKS.map(lit).join(', ')}]

    static let mappings: [ControlMapping] = [
`;
for (const m of c.CONTROL_MAPPINGS) {
  o += `        ControlMapping(framework: ${lit(m.framework)}, controlId: ${lit(m.controlId)}, controlTitle: ${lit(m.controlTitle)},\n` +
    `                       clause: ${lit(m.clause)},\n` +
    `                       requirement: ${lit(m.requirement)},\n` +
    `                       pcaEvidence: ${lit(m.pcaEvidence)},\n` +
    `                       evidenceFields: [${m.evidenceFields.map(lit).join(', ')}]),\n`;
}
o += '    ]\n}\n';
fs.writeFileSync(root + 'sdks/swift-pca/Sources/AtlasPCAVerify/ComplianceControls.swift', o);
console.log('wrote', c.CONTROL_MAPPINGS.length, 'mappings');
