// Post-build: append .js to relative imports in dist/*.js so Node's ESM
// resolver accepts them. Source files intentionally stay extensionless
// (faithful copies of Eclipse's src/net/); this rewrites emitted output only.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = 'dist';
const files = readdirSync(dir).filter((f) => f.endsWith('.js') || f.endsWith('.d.ts'));

// Match `from '...'` and `from "..."` where the target starts with `.` (relative)
// and doesn't already have a recognised extension.
const importRe = /(from\s+['"])(\.[^'"]+?)(['"])/g;

let touched = 0;
for (const f of files) {
  const p = join(dir, f);
  const src = readFileSync(p, 'utf8');
  const out = src.replace(importRe, (_, pre, spec, post) => {
    if (spec.endsWith('.js') || spec.endsWith('.json') || spec.endsWith('.mjs')) {
      return `${pre}${spec}${post}`;
    }
    return `${pre}${spec}.js${post}`;
  });
  if (out !== src) {
    writeFileSync(p, out);
    touched++;
  }
}
console.log(`fix-esm-extensions: rewrote ${touched} file(s)`);
