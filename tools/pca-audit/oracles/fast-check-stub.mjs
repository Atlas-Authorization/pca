// Stand-in for `fast-check`, used ONLY by invariants.mts (tsconfig.invariants.json maps the module here): the package builds its fast-check
// arbitraries at import time, and the oracle exercises only its deterministic exports, never a property. Every member and call yields the stub.
const stub = new Proxy(function () {}, { get: (_t, k) => (k === Symbol.toPrimitive ? () => 'stub' : stub), apply: () => stub, construct: () => stub });
export default stub;
