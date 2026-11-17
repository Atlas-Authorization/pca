/**
 * Project detection by `pca init`'s detector (`findApp` of @atlasauth/pca-init), behind this package's ProjectInspector seam, so a
 * coding agent and `npx @atlasauth/pca-cli init` see the same project. Facts `pca init` does not compute (an existing PCA
 * dependency, the coding-agent harnesses) come from the file inspector.
 */
import { AppChoiceError, findApp, type Detection as InitDetection } from '@atlasauth/pca-init';
import { fsInspector, recommend, type Detection, type Language, type ProjectInspector } from './detect';

const LANG: Record<InitDetection['language'], Language> = { js: 'javascript', python: 'python', ruby: 'ruby', go: 'go', java: 'java', dotnet: 'dotnet', php: 'php', rust: 'rust', swift: 'swift' };

export function fromInitDetection(base: Detection, d: InitDetection): Detection {
  const language = d.language === 'js' && d.typescript ? 'typescript' : LANG[d.language];
  const mcpSdk = d.agents.includes('MCP SDK');
  const out: Detection = {
    ...base,
    root: d.dir,
    name: d.ns,
    languages: [language],
    primaryLanguage: language,
    frameworks: [...(d.framework ? [d.framework] : []), ...d.agents].sort(),
    httpFrameworks: d.framework ? [d.framework] : [],
    mcpServer: mcpSdk || d.mcpServers.length > 0,
    agentCode: d.agents.some((a) => a !== 'MCP SDK'),
    openapi: d.openapi ? [d.openapi] : [],
    packageManager: d.packageManager,
  };
  out.recommendation = recommend(out);
  return out;
}

export const initInspector: ProjectInspector = {
  detect(root: string): Detection {
    const base = fsInspector.detect(root) as Detection;
    try {
      const app = findApp(root);
      return fromInitDetection(app.dir === root ? base : (fsInspector.detect(app.dir) as Detection), app);
    } catch (e) {
      if (e instanceof AppChoiceError) return /^more than one app/.test(e.message) ? { ...base, ambiguous: e.message } : base;
      throw e;
    }
  },
};
