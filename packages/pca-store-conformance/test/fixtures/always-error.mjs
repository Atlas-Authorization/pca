// Fails closed on every call: safe but gives no evidence (unresolved).
export default { name: 'fixture always error', capabilities: { durable: false }, open: async () => ({ advance: async () => { throw new Error('down'); } }) };
