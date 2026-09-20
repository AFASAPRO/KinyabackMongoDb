const Groq = require('groq-sdk');

const DEFAULT_MODEL = 'llama-3.3-70b-versatile';

let client;

function getClient() {
  if (!process.env.GROQ_API_KEY) {
    const error = new Error('GROQ_NOT_CONFIGURED');
    error.code = 'GROQ_NOT_CONFIGURED';
    throw error;
  }
  if (!client) client = new Groq({ apiKey: process.env.GROQ_API_KEY });
  return client;
}

function buildMessages({ history, systemPrompt, memory, ragContext, fileContext }) {
  const context = [];
  if (memory && Object.keys(memory).length) {
    context.push(`User context: ${Object.entries(memory).map(([key, value]) => `${key}=${value}`).join(', ')}`);
  }
  if (ragContext) context.push(ragContext.trim());
  if (fileContext) context.push(fileContext.trim());

  const messages = [];
  if (systemPrompt) messages.push({ role: 'system', content: systemPrompt.trim() });

  for (const message of history || []) {
    if (!['user', 'assistant'].includes(message.role) || !message.content?.trim()) continue;
    messages.push({ role: message.role, content: message.content.trim() });
  }

  if (context.length && messages.length) {
    const lastMessage = messages[messages.length - 1];
    if (lastMessage.role === 'user') lastMessage.content += `\n\n${context.join('\n\n')}`;
  }

  return messages;
}

async function complete({ history, systemPrompt, memory, ragContext, fileContext, maxTokens, temperature }) {
  const messages = buildMessages({ history, systemPrompt, memory, ragContext, fileContext });
  if (!messages.some(message => message.role === 'user')) {
    const error = new Error('INVALID_CONVERSATION');
    error.code = 'INVALID_CONVERSATION';
    throw error;
  }

  const completion = await getClient().chat.completions.create({
    model: process.env.GROQ_MODEL || DEFAULT_MODEL,
    messages,
    max_tokens: Number(maxTokens) || 2048,
    temperature: Number.isFinite(Number(temperature)) ? Number(temperature) : 0.7
  });

  const text = completion.choices?.[0]?.message?.content?.trim();
  if (!text) {
    const error = new Error('EMPTY_AI_RESPONSE');
    error.code = 'EMPTY_AI_RESPONSE';
    throw error;
  }
  return { text, model: process.env.GROQ_MODEL || DEFAULT_MODEL };
}

module.exports = { complete, buildMessages, DEFAULT_MODEL };