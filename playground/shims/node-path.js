// Browser stand-in for `node:path` (only `join`, used to build a candidate file path for the Node-only FN-DSA loader).
export function join(...parts) {
  return parts.join('/');
}
