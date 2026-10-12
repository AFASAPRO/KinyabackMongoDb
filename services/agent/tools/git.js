/**
 * KinyaBot Agent V1 — Git Tools (§8)
 * ─────────────────────────────────────────────────────────────
 * git_status · git_diff · git_log
 *
 * V1 policy: read-only inspection tools. Mutations (add/commit)
 * remain possible through run_command as MEDIUM risk (visible,
 * logged), while push/remote operations are HIGH risk and always
 * require user confirmation (§13: "Do NOT automatically push").
 */
const { registerTool } = require('./registry')
const { runRealCommand } = require('./terminal')
const { buildCommandEnv } = require('../sandbox')

async function git(ctx, args) {
  const result = await runRealCommand({
    command: `git ${args}`,
    cwd: ctx.workspace.root,
    env: buildCommandEnv(ctx.workspace.root),
    timeoutMs: Math.min(30_000, ctx.limits.commandTimeoutMs),
    maxOutputBytes: ctx.limits.commandMaxOutputBytes,
  })
  if (result.exitCode !== 0 && !/not a git repository|does not have any commits|nothing to commit|no changes/i.test(result.stderr || '')) {
    const e = new Error(`git ${args} failed: ${(result.stderr || result.stdout || '').trim().slice(0, 300)}`)
    e.code = 'GIT_ERROR'; e.userSafe = true
    throw e
  }
  return result
}

registerTool({
  name: 'git_status',
  description: 'Show the working tree status (git status --porcelain -b). Returns the branch and every changed file with its state. Reports "not a repository" honestly when the workspace has no git history.',
  parameters: { type: 'object', properties: {}, required: [] },
  permission: 'GIT', risk: 'low', category: 'git',
  handler: async ({ ctx }) => {
    const r = await git(ctx, 'status --porcelain=v1 -b')
    if (/not a git repository/i.test(r.stderr || '')) return { isRepository: false, branch: null, files: [] }
    const lines = (r.stdout || '').split('\n').filter(Boolean)
    const branch = lines[0]?.startsWith('## ') ? lines[0].slice(3).trim() : null
    const files = lines.slice(branch ? 1 : 0).map(l => ({
      state: l.slice(0, 2).trim(),
      path: l.slice(3).trim(),
    }))
    return { isRepository: true, branch, files, raw: r.stdout.slice(0, 4000) }
  },
})

registerTool({
  name: 'git_diff',
  description: 'Show the real diff of the working tree (git diff) and staged changes (git diff --cached). Empty output honestly means no changes.',
  parameters: {
    type: 'object',
    properties: {
      cached: { type: 'boolean', description: 'Show staged changes instead of working tree. Default false.' },
    },
    required: [],
  },
  permission: 'GIT', risk: 'low', category: 'git',
  handler: async ({ args, ctx }) => {
    const r = await git(ctx, `diff${args.cached ? ' --cached' : ''} --stat -p`)
    return { isRepository: !/not a git repository/i.test(r.stderr || ''), diff: (r.stdout || '').slice(0, 20000), empty: !(r.stdout || '').trim() }
  },
})

registerTool({
  name: 'git_log',
  description: 'Show the commit log (git log --oneline -n <n>). Default 20 entries.',
  parameters: {
    type: 'object',
    properties: {
      limit: { type: 'integer', description: 'Max commits to show (default 20, max 100).' },
    },
    required: [],
  },
  permission: 'GIT', risk: 'low', category: 'git',
  handler: async ({ args, ctx }) => {
    const n = Math.min(100, Math.max(1, Number(args.limit) || 20))
    const r = await git(ctx, `log --oneline -n ${n}`)
    if (/not a git repository|does not have any commits/i.test(r.stderr || '')) {
      return { isRepository: !/not a git repository/i.test(r.stderr || ''), commits: [] }
    }
    const commits = (r.stdout || '').split('\n').filter(Boolean).map(line => {
      const m = line.match(/^([0-9a-f]{7,})\s+(.*)$/)
      return m ? { hash: m[1], message: m[2] } : { hash: null, message: line }
    })
    return { isRepository: true, commits }
  },
})

module.exports = {}
