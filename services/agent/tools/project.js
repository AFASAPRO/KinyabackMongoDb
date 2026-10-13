/**
 * KinyaBot Agent V1 — Project Detection Tools (§23)
 * ─────────────────────────────────────────────────────────────
 * detect_project (full profile) plus the focused helpers the spec
 * names: detect_package_manager, detect_framework,
 * detect_dev_server, detect_build_command, detect_test_command.
 *
 * Detection is file-based and additive: FRAMEWORK_DETECTORS is a
 * declarative table, so adding Svelte/Next/Nuxt/Flask… in a later
 * version means appending entries — no loop changes.
 */
const fsp = require('fs').promises
const path = require('path')

const { registerTool } = require('./registry')

/* ── Declarative framework table (extend in V2+) ─────────────── */
const FRAMEWORK_DETECTORS = [
  { id: 'vue',         name: 'Vue 3',           signals: d => d.vite || d.nuxt || /\bvue\b/i.test(d.packageName || '') || (d.hasFile('src/App.vue') || d.hasFile('src/main.js')), runtimes: ['node'] },
  { id: 'react',       name: 'React',           signals: d => d.vite || d.next || /\breact\b/i.test(d.packageName || '') || d.hasFile('src/App.jsx') || d.hasFile('src/App.tsx'), runtimes: ['node'] },
  { id: 'svelte',      name: 'Svelte',          signals: d => /\bsvelte\b/i.test(d.packageName || '') || d.hasFile('src/App.svelte'), runtimes: ['node'] },
  { id: 'vite',        name: 'Vite',            signals: d => d.vite, runtimes: ['node'] },
  { id: 'next',        name: 'Next.js',         signals: d => d.next, runtimes: ['node'] },
  { id: 'nuxt',        name: 'Nuxt',            signals: d => d.nuxt, runtimes: ['node'] },
  { id: 'express',     name: 'Express',         signals: d => /\bexpress\b/i.test(d.packageName || ''), runtimes: ['node'] },
  { id: 'typescript',  name: 'TypeScript',      signals: d => d.hasFile('tsconfig.json'), runtimes: ['node'] },
  { id: 'node',        name: 'Node.js',         signals: d => d.hasFile('package.json'), runtimes: ['node'] },
  { id: 'python',      name: 'Python',          signals: d => d.hasFile('requirements.txt') || d.hasFile('pyproject.toml') || d.pyproject, runtimes: ['python'] },
  { id: 'static-html', name: 'Static HTML',     signals: d => d.hasFile('index.html'), runtimes: [] },
]

async function readJsonIfExists(abs) {
  try { return JSON.parse(await fsp.readFile(abs, 'utf8')) } catch { return null }
}

/** Shared scan used by every detection tool. */
async function scanProject(ctx) {
  const root = ctx.workspace.resolve('.')
  const pkg = await readJsonIfExists(path.join(root, 'package.json'))
  const exists = rel => {
    try { require('fs').statSync(ctx.workspace.resolve(rel)); return true } catch { return false }
  }

  const deps = { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) }
  const depNames = Object.keys(deps)
  const ctxData = {
    packageName: depNames.join(' '),
    vite: !!deps.vite || !!deps['@vitejs/plugin-vue'] || !!deps['@vitejs/plugin-react'],
    next: !!deps.next, nuxt: !!deps.nuxt || !!deps['nuxt'],
    pyproject: exists('pyproject.toml'),
    hasFile: exists,
  }

  // Frameworks: collect ALL matches (a Vite+Vue project reports both)
  const frameworks = FRAMEWORK_DETECTORS.filter(f => {
    try { return f.signals(ctxData) } catch { return false }
  }).map(f => ({ id: f.id, name: f.name, runtimes: f.runtimes }))

  // Package manager from lockfiles
  let packageManager = null
  if (exists('pnpm-lock.yaml')) packageManager = 'pnpm'
  else if (exists('yarn.lock')) packageManager = 'yarn'
  else if (exists('bun.lockb') || exists('bun.lock')) packageManager = 'bun'
  else if (exists('package-lock.json')) packageManager = 'npm'
  else if (pkg) packageManager = 'npm'

  const scripts = pkg?.scripts || {}
  const language = exists('tsconfig.json') ? 'typescript' : (pkg ? 'javascript' : (ctxData.pyproject || exists('requirements.txt') ? 'python' : (exists('index.html') ? 'html' : null)))

  /* V1.2 §3.E: plain static projects need NO server at all — the
     platform serves workspace files directly as the preview. Only
     package.json projects get a dev-server suggestion (their real
     `npm run dev`); Python projects may use http.server when the
     task genuinely needs a live backend.                            */
  const devServerCommand = scripts.dev
    ? 'npm run dev'
    : (frameworks.some(f => f.id === 'python') ? 'python3 -m http.server 8000' : null)
  const staticPreview = !pkg && frameworks.some(f => f.id === 'static-html')
    ? { note: 'Plain HTML/CSS/JS project — the platform previews it automatically. No server is needed.' }
    : null
  const buildCommand = scripts.build ? 'npm run build' : null
  const testCommand = scripts.test && scripts.test !== 'echo "Error: no test specified" && exit 1' ? 'npm test' : (language === 'python' && exists('tests') ? 'python -m pytest' : null)

  const entryPoints = []
  if (pkg?.main) entryPoints.push(pkg.main)
  if (pkg?.module) entryPoints.push(pkg.module)
  if (exists('src/main.js')) entryPoints.push('src/main.js')
  if (exists('src/main.ts')) entryPoints.push('src/main.ts')
  if (exists('src/index.js')) entryPoints.push('src/index.js')
  if (exists('src/App.vue')) entryPoints.push('src/App.vue')
  if (exists('index.html')) entryPoints.push('index.html')
  if (exists('app.py')) entryPoints.push('app.py')
  if (exists('server.js')) entryPoints.push('server.js')

  const sourceDirs = []
  for (const d of ['src', 'app', 'lib', 'components', 'pages', 'public', 'static', 'tests', 'test']) {
    if (exists(d)) sourceDirs.push(d)
  }

  return {
    hasProject: !!(pkg || exists('index.html') || exists('requirements.txt') || exists('pyproject.toml')),
    isPackageJson: !!pkg,
    packageJson: pkg ? { name: pkg.name || null, version: pkg.version || null, scripts, dependencies: Object.keys(pkg.dependencies || {}), devDependencies: Object.keys(pkg.devDependencies || {}) } : null,
    frameworks, language, packageManager,
    devServerCommand, staticPreview, buildCommand, testCommand,
    entryPoints: [...new Set(entryPoints)], sourceDirs,
  }
}

function registerAll() {
  registerTool({
    name: 'detect_project',
    description: 'Detect the project type in the workspace: framework(s), language, package manager, entry points, source directories and the dev/build/test commands. Run this FIRST when starting work on a project.',
    parameters: { type: 'object', properties: {}, required: [] },
    permission: 'READ', risk: 'low', category: 'project',
    handler: async ({ ctx }) => scanProject(ctx),
  })

  registerTool({
    name: 'detect_package_manager',
    description: 'Detect the package manager (npm, pnpm, yarn, bun) from lockfiles / package.json.',
    parameters: { type: 'object', properties: {}, required: [] },
    permission: 'READ', risk: 'low', category: 'project',
    handler: async ({ ctx }) => { const s = await scanProject(ctx); return { packageManager: s.packageManager, detectedFrom: s.isPackageJson ? 'lockfiles/package.json' : 'no package manifest found' } },
  })

  registerTool({
    name: 'detect_framework',
    description: 'Detect the framework(s) used by the workspace project (Vue, React, Vite, Express, Next, static HTML…).',
    parameters: { type: 'object', properties: {}, required: [] },
    permission: 'READ', risk: 'low', category: 'project',
    handler: async ({ ctx }) => { const s = await scanProject(ctx); return { frameworks: s.frameworks, language: s.language } },
  })

  registerTool({
    name: 'detect_dev_server',
    description: 'Detect the command that starts the development server for the workspace project, if any. Plain HTML/CSS/JS projects do NOT need one — the platform previews their files automatically after completion.',
    parameters: { type: 'object', properties: {}, required: [] },
    permission: 'READ', risk: 'low', category: 'project',
    handler: async ({ ctx }) => { const s = await scanProject(ctx); return { devServerCommand: s.devServerCommand, staticPreview: s.staticPreview || null, scripts: s.packageJson?.scripts || null } },
  })

  registerTool({
    name: 'detect_build_command',
    description: 'Detect the production build command for the workspace project, if any.',
    parameters: { type: 'object', properties: {}, required: [] },
    permission: 'READ', risk: 'low', category: 'project',
    handler: async ({ ctx }) => { const s = await scanProject(ctx); return { buildCommand: s.buildCommand, scripts: s.packageJson?.scripts || null } },
  })

  registerTool({
    name: 'detect_test_command',
    description: 'Detect the test command for the workspace project, if any.',
    parameters: { type: 'object', properties: {}, required: [] },
    permission: 'READ', risk: 'low', category: 'project',
    handler: async ({ ctx }) => { const s = await scanProject(ctx); return { testCommand: s.testCommand, scripts: s.packageJson?.scripts || null } },
  })
}

module.exports = { registerAll, scanProject, FRAMEWORK_DETECTORS }
