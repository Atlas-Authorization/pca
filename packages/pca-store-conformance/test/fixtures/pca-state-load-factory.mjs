export const createPcaStateAdapter = (o) => ({ name: 'ps factory ' + (o.label ?? 'none'), open: async () => ({ store: {} }) });
export default { name: 'ps default', open: async () => ({ store: {} }) };
