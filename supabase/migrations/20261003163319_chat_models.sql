-- Multi-model assistant: remember which model each conversation uses and which model wrote each reply.
-- Ids look like `anthropic:claude-opus-5-5`, `openai:gpt-5`, `mock:security-assistant`.

alter table public.chat_conversations
  add column model text not null default 'mock:security-assistant';

alter table public.chat_messages
  add column model text; -- null for the user's own messages

-- real models answer at length; 8000 chars was sized for the mock
alter table public.chat_messages drop constraint chat_messages_content_check;
alter table public.chat_messages
  add constraint chat_messages_content_check check (char_length(content) between 1 and 32000);
