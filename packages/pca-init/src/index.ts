// @atlasauth/pca-init: add PCA to an existing app with one command. See the README.
export * from './types';
export { findApp, detectDir, findMcpServers, AppChoiceError } from './detect';
export { makePlan, parseInitConfig, readInitConfig, addDependencies, InitError, type InitConfig } from './plan';
export { applyPlan, renderPlan, renderNext } from './apply';
export { checkInit } from './check';
export { routesOf, routesToOpenApi, importActions } from './imports';
export { editEntry, findAppVars, type RegSpec } from './ast';
export { runInit, parseInitArgs, INIT_USAGE } from './cli';
export { realGit, realDeps } from './git';
export { connectSource, DEFAULT_CONTROL_URL } from './connect';
