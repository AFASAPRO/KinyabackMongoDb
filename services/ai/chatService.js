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
  // Default: keep EVERYTHING (cutoff 0). Only when the newest-first
  // accumulation exceeds the budget do we drop the oldest messages.
  let total = 0, cutoff = 0
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

/* ── Recent image context (§18) ────────────────────────────────
   Returns the most recently shared image attachment so follow-up
   turns ("tell me more about this image") can re-attach it and
   the model can actually SEE it instead of confabulating.        */
function findRecentImageContext(history, { maxUserTurnsBack = 3 } = {}) {
  let userTurnsSeen = 0
  for (let i = history.length - 1; i >= 0; i--) {
    const m = history[i]
    if (m.role !== 'user') continue
    const imgAtt = (m.attachments || []).find(a => a.kind === 'image')
    if (imgAtt) return { name: imgAtt.name || 'image', url: imgAtt.url, mime: imgAtt.mime || 'image/jpeg' }
    userTurnsSeen++
    if (userTurnsSeen >= maxUserTurnsBack) break
  }
  return null
}

/* Human-visible placeholder for attachment-only messages so the
   model always knows a file was shared — empty content previously
   vanished from history, which made the model answer blindly.    */
function messageText(m) {
  const text = (m.content || '').trim()
  if (text) return text
  const att = (m.attachments || [])[0]
  if (!att) return ''
  if (att.kind === 'image') return `[User shared an image: ${att.name || 'photo'}]`
  if (att.kind === 'document')
    return `[User shared a document: ${att.name || 'file'}${att.pages ? ` (${att.pages} pages)` : ''}]`
  return `[User shared a file: ${att.name || 'attachment'}]`
}

/* ── Prompt assembly ─────────────────────────────────────────── */
function buildMessages({ systemPrompt, memory, ragContext, history, summary, documentContext, userText, imageDataUrl, priorImage }) {
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
  // Honesty guard (§6/§7): never pretend to see a file that is not in context.
  contextBlocks.push(
    'Attachment honesty: if the user refers to an image or document that is not present in your context, say clearly that you cannot see it right now and ask them to re-attach it. NEVER invent or describe a file you cannot see, and NEVER answer a question about an unseen attachment with a generic greeting.'
  )

  const messages = []
  const sys = [systemPrompt?.trim(), contextBlocks.length ? contextBlocks.join('\n\n') : '']
    .filter(Boolean).join('\n\n')
  if (sys) messages.push({ role: 'system', content: sys })

  for (const m of history) {
    if (!['user', 'assistant'].includes(m.role)) continue
    const text = messageText(m)
    if (!text) continue
    messages.push({ role: m.role, content: text })
  }

  // Final user turn. Three shapes:
  //   1. new image this turn → multimodal parts (text + image)
  //   2. follow-up about an earlier image → re-attach it (§18)
  //   3. plain text (attachment-only turns get a default prompt so a
  //      user turn ALWAYS exists — prevents greeting prefills)
  const trimmedUserText = (userText || '').trim()
  if (imageDataUrl) {
    while (messages.length && messages[messages.length - 1].role === 'user') messages.pop()
    messages.push({
      role: 'user',
      content: [
        { type: 'text', text: trimmedUserText || 'What is in this image? Describe it in detail.' },
        { type: 'image_url', image_url: { url: imageDataUrl } },
      ],
    })
  } else if (priorImage?.dataUrl) {
    while (messages.length && messages[messages.length - 1].role === 'user') messages.pop()
    messages.push({
      role: 'user',
      content: [
        { type: 'text', text: trimmedUserText || 'What is in this image? Describe it in detail.' },
        { type: 'text', text: `(This is the image the user shared earlier in this conversation: ${priorImage.name})` },
        { type: 'image_url', image_url: { url: priorImage.dataUrl } },
      ],
    })
  } else if (trimmedUserText) {
    const last = messages[messages.length - 1]
    if (last && last.role === 'user' && last.content === trimmedUserText) {
      // already appended via history — nothing to do
    } else {
      // An attachment-only placeholder (e.g. "[User shared a document: …]")
      // is replaced by the explicit request the caller synthesized.
      if (last && last.role === 'user' && last.content.startsWith('[User shared')) messages.pop()
      messages.push({ role: 'user', content: trimmedUserText })
    }
  } else if (documentContext) {
    // Attachment-only document turn: give the model an explicit request
    const last = messages[messages.length - 1]
    if (last && last.role === 'user' && last.content.startsWith('[User shared')) messages.pop()
    messages.push({ role: 'user', content: 'Please read the attached document and tell me what it contains.' })
  }
  // NOTE: never leave the transcript ending on a system/assistant
  // message — some models prefill a greeting in that case.

  return messages
}

/* Choose the model for this turn (§4): vision whenever the model can
   actually see an image (new or re-attached), otherwise chat model. */
function pickModel({ imageDataUrl, priorImage } = {}) {
  if (imageDataUrl || priorImage?.dataUrl) return config.models.vision
  return config.models.chat
}

module.exports = {
  loadHistory,
  trimToBudget,
  ensureSummary,
  findRecentDocumentContext,
  findRecentImageContext,
  messageText,
  buildMessages,
  pickModel,
  CHARS_PER_TOKEN,
}
