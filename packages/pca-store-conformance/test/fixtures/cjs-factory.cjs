// CommonJS module whose exports object carries the factory.
exports.createAdapter = () => ({ name: 'fixture cjs', capabilities: { durable: false }, open: async () => ({ advance: async () => false }) });
