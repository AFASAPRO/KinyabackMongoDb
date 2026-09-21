/**
 * KinyaBot — Legacy AI service entry (backward-compatible shim)
 * ─────────────────────────────────────────────────────────────
 * The real implementation now lives in services/ai/ (AI Core):
 *   groqProvider  – single Groq integration point
 *   chatService   – context management / prompt assembly
 *   documentService / speechService – multimodal capabilities
 *
 * This module keeps the historical `complete()` / `buildMessages()`
 * API so existing callers (admin AI test panel) keep working while
 * new code should use the AI Core services directly.
 */
const provider = require('./services/ai/groqProvider')
const config = require('./services/ai/config')

const DEFAULT_MODEL = provider.DEFAULT_MODEL

function buildMessages({ history, systemPrompt, memory, ragContext, fileContext }) {
  const context = []
  if (memory && Object.keys(memory).length) {
    context.push(`User context: ${Object.entries(memory).map(([key, value]) => `${key}=${value}`).join(', ')}`)
  }
  if (ragContext) context.push(ragContext.trim())
  if (fileContext) context.push(fileContext.trim())

  const messages = []
  if (systemPrompt) messages.push({ role: 'system', content: systemPrompt.trim() })

  for (const message of history || []) {
    if (!['user', 'assistant'].includes(message.role) || !message.content?.trim()) continue
    messages.push({ role: message.role, content: message.content.trim() })
  }

  if (context.length && messages.length) {
    const lastMessage = messages[messages.length - 1]
    if (lastMessage.role === 'user') lastMessage.content += `\n\n${context.join('\n\n')}`
  }

  return messages
}

async function complete({ history, systemPrompt, memory, ragContext, fileContext, maxTokens, temperature }) {
  const messages = buildMessages({ history, systemPrompt, memory, ragContext, fileContext })
  if (!messages.some(message => message.role === 'user')) {
    const error = new Error('INVALID_CONVERSATION')
    error.code = 'INVALID_CONVERSATION'
    throw error
  }

  const result = await provider.chatComplete({
    messages,
    model: process.env.GROQ_CHAT_MODEL || process.env.GROQ_MODEL || config.models.chat,
    maxTokens: Number(maxTokens) || 2048,
    temperature: Number.isFinite(Number(temperature)) ? Number(temperature) : 0.7,
  })
  return { text: result.text, model: result.model }
}

module.exports = { complete, buildMessages, DEFAULT_MODEL }
