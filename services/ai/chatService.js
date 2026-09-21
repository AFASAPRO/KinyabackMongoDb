/**
 * KinyaBot AI Core — Chat Service
 * ─────────────────────────────────────────────────────────────
 * Conversation context management (§5) + prompt assembly.
 *
 *   • Sends a bounded window of recent history (never unlimited).
 *   • Enforces a character budget and trims oldest-first.
 *   • For very long conversations, maintains a rolling summary so
 *     earlier context is not silently lost.
 *   • Injects the most recent document context so follow-up
 *     questions ("What did the author say in chapter 2?") work
 *     without re-uploading (§18).
 *   • Attaches images to the current user turn as multimodal
 *     content parts routed to the vision model (§8).
 */
const { Chat, Message } = require('../../models')
const { chatComplete } = require('./groqProvider')
const config = require('./config')
const documentService = require('./documentService')

const CHARS_PER_TOKEN = 4

/* ── Load + bound history ────────────────────────────────────── */
async function loadHistory(chatId, { excludeMessageId = null } = {}) {
  const rows = await Message.find({ chat_id: chatId })
    .sort({ created_at: -1, _id: -1 })
    .limit(Math.max(config.context.maxMessages, config.context.summarizeAfter) + 4)
    .lean()
  let history = rows.reverse()
  if (excludeMessageId) history = history.filter(m => String(m._id) !== String(excludeMessageId))
  return history
}

function trimToBudget(history, budgetTokens = config.context.tokenBudget) {
  const budgetChars = budgetTokens * CHARS_PER_TOKEN
  let total = 0, cutoff = history.length
  for (let i = history.length - 1; i >= 0; i--) {
    total += (history[i].content || '').length
    if (total > budgetChars && history.length - i > 2) { cutoff = i + 1; break }
  }
  return { kept: history.slice(cutoff), droppedCount: cutoff }
}

/* ── Rolling summary for very long conversations (§5) ────────── */
async function ensureSummary(chat, history, droppedCount) {
  const totalMessages = await Message.countDocuments({ chat_id: chat._id })
  if (totalMessages < config.context.summarizeAfter) return null

  // Reuse a fresh summary if the conversation barely moved since
  if (chat.summary && chat.summary_depth &&
      totalMessages - chat.summary_depth < config.context.summarizeAfter / 2) {
    return chat.summary
  }

  try {
    const source = history.slice(0, Math.max(6, droppedCount || 6))
      .map(m => `${m.role === 'user' ? 'User' : 'Assistant'}: ${(m.content || '').slice(0, 400)}`)
      .join('\n')
    if (!source.trim()) return null
    const { text } = await chatComplete({
      messages: [
        { role: 'system', content: 'Summarize the key facts, questions, decisions and names from this conversation in under 150 words. Preserve specifics the user would expect the assistant to remember later. Output only the summary.' },
        { role: 'user', content: source },
      ],
      maxTokens: config.context.summaryMaxTokens,
      temperature: 0.3,
    })
    chat.summary = text
    chat.summary_depth = totalMessages
    await Chat.updateOne({ _id: chat._id }, { $set: { summary: text, summary_depth: totalMessages } })
    return text
  } catch { return null } // summarization must never break the chat
}

/* ── Document context from conversation (§18) ───────────────── */
function findRecentDocumentContext(history) {
  for (let i = history.length - 1; i >= 0; i--) {
    const m = history[i]
    if (m.role !== 'user') continue
    const docAtt = (m.attachments || []).find(a => a.kind === 'document' && a.extracted_text)
    if (docAtt) {
      return {
        name: docAtt.name,
        pages: docAtt.pages || null,
        text: documentService.followContext(docAtt.extracted_text),
      }
    }
  }
  return null
}

/* ── Prompt assembly ─────────────────────────────────────────── */
function buildMessages({ systemPrompt, memory, ragContext, history, summary, documentContext, userText, imageDataUrl }) {
  const contextBlocks = []
  if (memory && Object.keys(memory).length) {
    contextBlocks.push(`User context: ${Object.entries(memory).map(([k, v]) => `${k}=${v}`).join(', ')}`)
  }
  if (summary) contextBlocks.push(`Summary of earlier conversation:\n${summary}`)
  if (ragContext) contextBlocks.push(ragContext.trim())
  if (documentContext) {
    const pages = documentContext.pages ? ` (${documentContext.pages} pages)` : ''
    contextBlocks.push(`[Attached document: ${documentContext.name}${pages}]\nThe user previously uploaded this document. Answer questions about it from this content; say clearly when something is not in the document.\n---\n${documentContext.text}\n---`)
  }

  const messages = []
  const sys = [systemPrompt?.trim(), contextBlocks.length ? contextBlocks.join('\n\n') : '']
    .filter(Boolean).join('\n\n')
  if (sys) messages.push({ role: 'system', content: sys })

  for (const m of history) {
    if (!['user', 'assistant'].includes(m.role) || !m.content?.trim()) continue
    messages.push({ role: m.role, content: m.content.trim() })
  }

  // Final user turn (may carry an image → multimodal content parts).
  // The trailing user message is dropped from history when an image is
  // attached, otherwise its text would be sent twice (plain + multimodal).
  if (imageDataUrl) {
    while (messages.length && messages[messages.length - 1].role === 'user') messages.pop()
    messages.push({
      role: 'user',
      content: [
        { type: 'text', text: userText || 'What is in this image?' },
        { type: 'image_url', image_url: { url: imageDataUrl } },
      ],
    })
  } else if (userText) {
    const last = messages[messages.length - 1]
    if (last && last.role === 'user' && last.content === userText.trim()) {
      // already appended via history — nothing to do
    } else {
      messages.push({ role: 'user', content: userText })
    }
  }

  return messages
}

/* Choose the model for this turn (§4): vision when an image is
   present, otherwise the configured chat model. */
function pickModel({ imageDataUrl, documentUsed }) {
  if (imageDataUrl) return config.models.vision
  return config.models.chat
}

module.exports = {
  loadHistory,
  trimToBudget,
  ensureSummary,
  findRecentDocumentContext,
  buildMessages,
  pickModel,
  CHARS_PER_TOKEN,
}
