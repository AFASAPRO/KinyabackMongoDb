/**
 * KinyaBot Agent V1 — Scripted TEST Provider (§37 Testing)
 * ─────────────────────────────────────────────────────────────
 * ⚠ TEST-ONLY — never active in production. Selected exclusively
 * through AGENT_PROVIDER=scripted while NODE_ENV=test (enforced
 * by agentProvider.getAgentProvider()).
 *
 * Why it exists: the automated test suite must exercise the REAL
 * system — real orchestrator, real forked worker, real sandbox,
 * real filesystem tools, real terminal commands, real MongoDB
 * persistence and real Socket.IO events. This provider replaces
 * ONLY the model decision layer with deterministic scripts, so
 * the exact same code paths run end-to-end without network
 * access to Groq (which this sandbox cannot reach).
 *
 * Each script is a list of model turns. A turn is either:
 *   { tool_calls: [{ name, arguments }] }   → the model asks for tools
 *   { content: '...' }                      → the model answers
 * The runner replays them in order and throws when a script runs
 * out (tests would otherwise loop forever — fail fast instead).
 *
 * Scripts reference the acceptance-test prompts defined in
 * tests/agent/. Every tool call they request is REAL: files are
 * really created on disk, commands really execute, output is
 * really captured.
 */

const SCRIPTS = {
  /* §38 acceptance test — a realistic multi-step task.
     Verification is REAL: read_file actually reads the created file
     from disk before VERIFIED is claimed. */
  'Create a simple HTML page about KinyaBot.': {
    plan: ['Inspect the workspace', 'Create the HTML page', 'Verify the file exists', 'Report completion'],
    turns: [
      { tool_calls: [{ name: 'detect_project', arguments: {} }] },
      { tool_calls: [{ name: 'create_file', arguments: {
        path: 'index.html',
        content: '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<title>KinyaBot</title>\n<style>body{font-family:system-ui;display:grid;place-items:center;min-height:100vh;margin:0;background:#070A12;color:#F8FAFC}h1{font-size:2.4rem}</style>\n</head>\n<body>\n<main>\n<h1>KinyaBot AI</h1>\n<p>Your intelligent assistant.</p>\n</main>\n</body>\n</html>\n',
      } }] },
      { tool_calls: [{ name: 'run_command', arguments: { command: 'ls -la index.html && head -5 index.html' } }] },
      { content: 'Created index.html — a clean dark-themed landing page for KinyaBot. Verified: the file exists on disk (ls) and its first lines read back correctly.' },
    ],
    verification: [
      { tool_calls: [{ name: 'read_file', arguments: { path: 'index.html' } }] },
      { content: 'VERIFIED: read index.html back from disk — it contains the complete KinyaBot page markup.' },
    ],
  },

  /* §37 integration test — preview architecture exercised for real.
     The port is DYNAMICALLY allocated (bind to port 0, read back the
     free port) and persisted in .port so follow-up commands reuse it:
     hermetic — no fixed-port collisions between test runs.        */
  'Serve a static site and verify it is running.': {
    plan: ['Create the page', 'Start a static server', 'Verify the server responds', 'Report'],
    turns: [
      { tool_calls: [{ name: 'create_file', arguments: {
        path: 'index.html',
        content: '<!DOCTYPE html>\n<html><head><title>Static</title></head><body><h1>Agent preview works</h1></body></html>\n',
      } }] },
      { tool_calls: [{ name: 'run_command', arguments: { background: true, command: 'P=$(python3 -c \'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()\'); echo $P > .port; exec python3 -m http.server $P' } }] },
      { tool_calls: [{ name: 'run_command', arguments: { command: 'curl -s http://127.0.0.1:$(cat .port)/ | head -3' } }] },
      { content: 'Started a static python http server in the background on a free port, verified with curl that the page is served, and the preview is live.' },
    ],
    verification: [
      { tool_calls: [{ name: 'run_command', arguments: { command: 'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$(cat .port)/' } }] },
      { content: 'VERIFIED: the preview server answered HTTP 200 on the dynamically allocated port.' },
    ],
  },

  /* Failure-recovery test: the model tries a wrong path, reads the
     honest error, self-corrects and continues. */
  'Fix the file at src/app.js.': {
    plan: ['Read the existing file', 'Apply a targeted edit', 'Verify the edit'],
    turns: [
      { tool_calls: [{ name: 'read_file', arguments: { path: 'src/app.js' } }] },
      { tool_calls: [{ name: 'edit_file', arguments: { path: 'src/app.js', find: 'TODO: implement', replace: 'console.log("implemented")' } }] },
      { tool_calls: [{ name: 'read_file', arguments: { path: 'src/app.js' } }] },
      { content: 'Applied the targeted edit to src/app.js and read the file back to confirm the change.' },
    ],
    verification: [
      { tool_calls: [{ name: 'search_files', arguments: { query: 'TODO' } }] },
      { content: 'VERIFIED: no TODO marker remains in src/app.js — the edit is on disk.' },
    ],
  },

  /* Command-safety test: creates a REAL file first, then requests a
     blocked command, receives the honest refusal, then proceeds
     safely — so "workspace files intact" is a meaningful assertion. */
  'Try to remove everything then list files.': {
    plan: ['Create a work file', 'Attempt the requested cleanup', 'List remaining files'],
    turns: [
      { tool_calls: [{ name: 'create_file', arguments: { path: 'notes.txt', content: 'Important scratch notes.\nDo not delete.\n' } }] },
      { tool_calls: [{ name: 'run_command', arguments: { command: 'rm -rf /' } }] },
      { tool_calls: [{ name: 'list_files', arguments: { path: '.' } }] },
      { content: 'The destructive command was blocked by the safety policy. Listed the workspace files instead — notes.txt is intact.' },
    ],
    verification: [
      { tool_calls: [{ name: 'read_file', arguments: { path: 'notes.txt' } }] },
      { content: 'VERIFIED: notes.txt still exists with its original content after the blocked deletion attempt.' },
    ],
  },

  /* High-risk confirmation flow test. */
  'Push the repository to production.': {
    plan: ['Attempt the push', 'Report the outcome'],
    turns: [
      { tool_calls: [{ name: 'run_command', arguments: { command: 'git push origin main' } }] },
      { content: 'The git push was declined by the user, so nothing was pushed to the remote.' },
    ],
    verification: [
      { content: 'VERIFIED: no push command executed — the task honestly reported the declined operation.' },
    ],
  },

  /* Cancellation test (§17): a REAL long-running command guarantees
     the worker is mid-execution when the user stops the task — the
     cancel must kill the process tree and mark state 'cancelled'. */
  'Run the long build and report results.': {
    plan: ['Run the build', 'Report the results'],
    turns: [
      { tool_calls: [{ name: 'run_command', arguments: { command: 'sleep 30 && echo build-done' } }] },
      { content: 'The build finished.' },
    ],
    verification: [
      { content: 'VERIFIED: build completed.' },
    ],
  },
}

class ScriptedRunner {
  constructor(taskKey, phase = 'execution') {
    this.taskKey = taskKey
    this.phase = phase
    const script = SCRIPTS[taskKey]
    this.turns = phase === 'verification'
      ? (script?.verification || [{ content: 'VERIFIED: checked.' }])
      : (script?.turns || null)
    this.cursor = 0
  }

  step(messages) {
    if (!this.turns) {
      throw Object.assign(
        new Error(`No scripted behavior for task: "${this.taskKey}" — add it to SCRIPTS`),
        { code: 'SCRIPT_MISSING' }
      )
    }
    const turn = this.turns[this.cursor]
    this.cursor += 1
    if (!turn) {
      throw Object.assign(
        new Error(`Script exhausted for "${this.taskKey}" (${this.phase}) at step ${this.cursor}`),
        { code: 'SCRIPT_EXHAUSTED' }
      )
    }
    return Promise.resolve({
      message: {
        role: 'assistant',
        content: turn.content || '',
        tool_calls: (turn.tool_calls || []).map((c, i) => ({
          id: `call_${this.phase}_${this.cursor}_${i}`,
          type: 'function',
          function: { name: c.name, arguments: JSON.stringify(c.arguments ?? {}) },
        })),
      },
      finish_reason: turn.tool_calls ? 'tool_calls' : 'stop',
      model: 'scripted-test-provider',
      tokens: 0,
    })
  }
}

module.exports = { SCRIPTS, ScriptedRunner }
