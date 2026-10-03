-- Developer role: may only use the AI security assistant, nothing else in the console.
-- Kept in its own migration: a new enum value can't be used in the transaction that adds it.
alter type public.team_role add value if not exists 'developer';
