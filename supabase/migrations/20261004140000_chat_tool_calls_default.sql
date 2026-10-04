-- chat_messages.tool_calls as it already is on the hosted project: never null,
-- an empty list when a reply took no tool steps. 20261004130000 created it
-- nullable; the live column was made not null with this default outside the
-- migrations. This brings every other database in line and is a no-op there.
update public.chat_messages set tool_calls = '[]'::jsonb where tool_calls is null;
alter table public.chat_messages
  alter column tool_calls set default '[]'::jsonb,
  alter column tool_calls set not null;
