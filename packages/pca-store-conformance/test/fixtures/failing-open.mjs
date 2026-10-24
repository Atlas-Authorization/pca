export default { name: 'fixture failing open', open: async () => { throw new Error('connection refused'); } };
