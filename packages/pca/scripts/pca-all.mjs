// The generators use names from the root entry and from the extension subpaths (the intent layer moved to
// `@atlasauth/pca/ext/intent` in 0.5). PCA_SRC=1 loads the TypeScript source instead of dist.
export async function loadPca() {
  const [dir, ext] = process.env.PCA_SRC ? ['../src', '.ts'] : ['../dist', '.js'];
  const mods = await Promise.all(['index', 'ext/intent'].map((m) => import(`${dir}/${m}${ext}`)));
  return Object.assign({}, ...mods);
}
