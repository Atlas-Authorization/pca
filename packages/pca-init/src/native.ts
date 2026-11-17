/**
 * Other languages: the install command and the exact snippet to paste. These are never edited blindly: no parser for them is
 * available here, so the CLI prints the snippet and the file and line it belongs at. The SDK middleware has no observe mode, so the
 * snippet registers the guard only when `PCA_MODE=enforce`; to observe before that, use `pca init --proxy` (no code at all).
 */
import { relative } from 'node:path';
import { listFiles, read } from './detect';
import type { Detection, Snippet } from './types';
import { GRANT_FILE } from './wiring';

export interface NativeGuide {
  install: string[];
  snippet: Snippet;
}

interface Where {
  exts: string[];
  re: RegExp;
  hint: string;
}

/** The first file and line matching `re`, as `path:line`. */
function locate(d: Detection, w: Where): string | null {
  for (const f of listFiles(d.dir, w.exts, { limit: 600 })) {
    const t = read(f);
    if (t === null) continue;
    const lines = t.split('\n');
    const i = lines.findIndex((l) => w.re.test(l));
    if (i >= 0) return `${relative(d.dir, f)}:${i + 1}`;
  }
  return null;
}

const where = (d: Detection, w: Where): string => {
  const at = locate(d, w);
  return at === null ? w.hint : `${at} (${w.hint})`;
};

export function nativeGuide(d: Detection, aud: string): NativeGuide | null {
  const ns = d.ns;
  const fw = d.framework;
  const grant = GRANT_FILE;
  switch (d.language) {
    case 'python': {
      if (fw === 'fastapi') {
        return {
          install: ['pip install "atlas-pca[fastapi,fast]"'],
          snippet: {
            title: 'FastAPI dependency (atlas-pca)',
            where: where(d, { exts: ['.py'], re: /\bFastAPI\(/, hint: 'above the line that creates the app, and pass dependencies=_pca_guard() to FastAPI(...)' }),
            code: `import json, os
from fastapi import Depends
from atlas_pca import protect
from atlas_pca.fastapi import RequirePCA

def _pca_guard():
    if os.environ.get("PCA_MODE") != "enforce":
        return []
    p = protect("${aud}", [json.load(open("${grant}"))],
                operation=lambda request, body: {"verb": "${ns}." + request.method.lower(), "resource": request.url.path, "params": {}})
    return [Depends(RequirePCA(**p.options))]

# then:  app = FastAPI(dependencies=_pca_guard())`,
          },
        };
      }
      if (fw === 'flask') {
        return {
          install: ['pip install "atlas-pca[flask,fast]"'],
          snippet: {
            title: 'Flask (atlas-pca)',
            where: where(d, { exts: ['.py'], re: /\bFlask\(__name__\)/, hint: 'after the line that creates the app' }),
            code: `import json, os
from atlas_pca import protect
from atlas_pca.flask import PCAFlask

if os.environ.get("PCA_MODE") == "enforce":
    p = protect("${aud}", [json.load(open("${grant}"))],
                operation=lambda request: {"verb": "${ns}." + request.method.lower(), "resource": request.path, "params": {}})
    PCAFlask(**p.options).init_app(app)`,
          },
        };
      }
      if (fw === 'django') {
        return {
          install: ['pip install "atlas-pca[django,fast]"'],
          snippet: {
            title: 'Django middleware (atlas-pca)',
            where: where(d, { exts: ['settings.py'], re: /^MIDDLEWARE\s*=/, hint: 'the end of your settings module' }),
            code: `import json, os
if os.environ.get("PCA_MODE") == "enforce":
    from atlas_pca import protect
    _p = protect("${aud}", [json.load(open("${grant}"))],
                 operation=lambda request: {"verb": "${ns}." + request.method.lower(), "resource": request.path, "params": {}})
    MIDDLEWARE += ["atlas_pca.django.PCAMiddleware"]
    PCA_AUDIENCE = _p.options["audience"]
    PCA_RESOLVE_GRANT = _p.options["resolve_grant"]
    PCA_AUTHORIZE = _p.options["authorize"]
    PCA_OPERATION = _p.options["operation"]`,
          },
        };
      }
      return null;
    }
    case 'ruby': {
      const mount = fw === 'rails' ? 'config.middleware.use AtlasPca::RackMiddleware, **prot.options' : 'use AtlasPca::RackMiddleware, **prot.options';
      return {
        install: ['bundle add atlas-pca'],
        snippet: {
          title: `${fw === 'rails' ? 'Rails' : 'Sinatra'} Rack middleware (atlas-pca)`,
          where: fw === 'rails' ? where(d, { exts: ['application.rb'], re: /class Application/, hint: 'inside the Application class' }) : where(d, { exts: ['.rb'], re: /sinatra/i, hint: 'after the line that requires sinatra' }),
          code: `require 'atlas_pca'
require 'json'

if ENV['PCA_MODE'] == 'enforce'
  prot = AtlasPca.protect(audience: '${aud}', grants: [JSON.parse(File.read('${grant}'))],
                          operation: ->(env) { { verb: "${ns}.#{env['REQUEST_METHOD'].downcase}", resource: env['PATH_INFO'], params: {} } })
  ${mount}
end`,
        },
      };
    }
    case 'go': {
      return {
        install: ['go get github.com/Atlas-Authorization/pca-go'],
        snippet: {
          title: 'net/http middleware (pca-go)',
          where: where(d, { exts: ['.go'], re: /ListenAndServe|http\.Server\{|\.Run\(/, hint: 'where the server is started; wrap the handler you pass to it' }),
          code: `import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	pca "github.com/Atlas-Authorization/pca-go"
)

func withPCA(next http.Handler) http.Handler {
	if os.Getenv("PCA_MODE") != "enforce" {
		return next
	}
	raw, err := os.ReadFile("${grant}")
	if err != nil {
		panic("PCA enforce mode needs ${grant}: " + err.Error())
	}
	var grant map[string]any
	if err := json.Unmarshal(raw, &grant); err != nil {
		panic(err)
	}
	p := pca.Protect(pca.ProtectOptions{
		Audience: "${aud}",
		Grants:   []map[string]any{grant},
		Operation: func(r *http.Request, body []byte) (*pca.Operation, error) {
			return &pca.Operation{Verb: "${ns}." + strings.ToLower(r.Method), Resource: r.URL.Path, Params: map[string]any{}}, nil
		},
	})
	return p.Middleware()(next)
}

// then:  http.ListenAndServe(addr, withPCA(yourHandler))`,
        },
      };
    }
    case 'java': {
      if (fw !== 'spring-boot') return null;
      return {
        install: ['build the SDK once: see sdks/java-pca/adapters/pca-spring-boot-starter/README.md, then add net.atlasauth:pca-spring-boot-starter to your build'],
        snippet: {
          title: 'Spring Boot starter (pca-spring-boot-starter)',
          where: where(d, { exts: ['application.yml', 'application.yaml'], re: /./, hint: 'src/main/resources/application.yml' }),
          code: `# application.yml
pca:
  audience: ${aud}
  store: memory
  grants-location: file:${grant}   # a JSON array: [ <the grant> ]
  exclude-path-patterns: /health

// and one bean, the operation YOUR route executes:
@Bean PcaFilter.OperationMapper operation() {
    return (request, body) -> Authorize.Operation.of("${ns}." + request.getMethod().toLowerCase(), request.getRequestURI(), java.util.Map.of());
}`,
        },
      };
    }
    case 'dotnet': {
      if (fw !== 'aspnetcore') return null;
      return {
        install: ['dotnet add package AtlasPca.AspNetCore'],
        snippet: {
          title: 'ASP.NET Core middleware (AtlasPca.AspNetCore)',
          where: where(d, { exts: ['Program.cs'], re: /\bbuilder\.Build\(\)/, hint: 'right after var app = builder.Build();' }),
          code: `if (Environment.GetEnvironmentVariable("PCA_MODE") == "enforce")
{
    var grant = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object?>>(File.ReadAllText("${grant}"))!;
    var pca = PcaProtect.Create("${aud}", new[] { grant },
        ctx => Task.FromResult<Operation?>(new Operation("${ns}." + ctx.Request.Method.ToLowerInvariant(), ctx.Request.Path.Value ?? "/", new Dictionary<string, object?>())));
    app.UsePcaProtect(pca);
}`,
        },
      };
    }
    case 'php': {
      if (fw === 'laravel') {
        return {
          install: ['composer require atlas-auth/atlas-pca'],
          snippet: {
            title: 'Laravel route middleware (atlas-auth/atlas-pca)',
            where: where(d, { exts: ['api.php', 'web.php'], re: /Route::/, hint: 'routes/api.php: group the routes you want guarded; config/pca.php supplies pca.middleware (see the package README)' }),
            code: `// config/pca.php
return [
    'middleware' => fn ($app) => \\Atlas\\Pca\\Protect::protect([
        'audience'  => '${aud}',
        'grants'    => [json_decode(file_get_contents(base_path('${grant}')), false)],
        'operation' => fn ($req) => ['verb' => '${ns}.' . strtolower($req->getMethod()), 'resource' => $req->getUri()->getPath(), 'params' => []],
    ])->middleware,
];

// routes/api.php (only when PCA_MODE=enforce):
Route::middleware(env('PCA_MODE') === 'enforce' ? ['pca'] : [])->group(function () {
    // your routes
});`,
          },
        };
      }
      if (fw === 'symfony') {
        return {
          install: ['composer require atlas-auth/atlas-pca'],
          snippet: {
            title: 'PSR-15 middleware (atlas-auth/atlas-pca)',
            where: where(d, { exts: ['.php'], re: /MiddlewareInterface|public\/index\.php|Kernel/, hint: 'where you build your PSR-15 pipeline' }),
            code: `$p = \\Atlas\\Pca\\Protect::protect([
    'audience'  => '${aud}',
    'grants'    => [json_decode(file_get_contents('${grant}'), false)],
    'operation' => fn ($req) => ['verb' => '${ns}.' . strtolower($req->getMethod()), 'resource' => $req->getUri()->getPath(), 'params' => []],
]);
// add $p->middleware to the pipeline only when getenv('PCA_MODE') === 'enforce'`,
          },
        };
      }
      return null;
    }
    case 'rust': {
      if (fw !== 'axum') return null;
      return {
        install: ['cargo add atlas-pca --features axum'],
        snippet: {
          title: 'axum layer (atlas-pca)',
          where: where(d, { exts: ['.rs'], re: /Router::new\(\)/, hint: 'where the Router is built' }),
          code: `use atlas_pca::protect::{protect, ProtectOptions};
use atlas_pca::Operation;

let app = if std::env::var("PCA_MODE").as_deref() == Ok("enforce") {
    let grant: serde_json::Value = serde_json::from_str(&std::fs::read_to_string("${grant}").expect("PCA enforce mode needs ${grant}")).unwrap();
    let p = protect(ProtectOptions::new("${aud}", vec![grant], |parts, _body| {
        Some(Operation::new(format!("${ns}.{}", parts.method.as_str().to_lowercase()), parts.uri.path(), serde_json::json!({})))
    }));
    app.layer(p.layer())
} else {
    app
};`,
        },
      };
    }
    case 'swift': {
      if (fw !== 'vapor') return null;
      return {
        install: ['add the AtlasPCAVapor product of the swift-pca package to Package.swift (see sdks/swift-pca/README.md)'],
        snippet: {
          title: 'Vapor middleware (AtlasPCAVapor)',
          where: where(d, { exts: ['configure.swift'], re: /func configure/, hint: 'inside configure(_ app:)' }),
          code: `if Environment.get("PCA_MODE") == "enforce" {
    let grant = try JSONValue.parse(String(contentsOfFile: "${grant}"))!
    let p = protect(audience: "${aud}", operation: { req in
        PCA.Operation(verb: "${ns}." + req.method.lowercased(), resource: req.path, params: .object([:]))
    }, grants: [grant])
    app.middleware.use(try p.middleware())
}`,
        },
      };
    }
    default:
      return null;
  }
}
