-- The MCP tool calls behind an assistant reply: tool, status, and the
-- `result_id` of rows the gateway delivered to the user (never to the model).
-- Kept so a reloaded conversation still shows its steps and its results.
alter table public.chat_messages
  add column tool_calls jsonb not null default '[]'::jsonb;
