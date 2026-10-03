-- Demo data. Deterministic on purpose: the demo script depends on these exact
-- slugs and limits.

insert into principals (slug, display_name, kind, allowed_models, allowed_tools)
values
  -- A well-behaved agent with a narrow tool grant. It may read documents but
  -- not enumerate them.
  ('demo-agent', 'Demo agent', 'agent',
   array['llama3.1:8b', 'qwen2.5:7b'],
   array['docs__read', 'docs__search']),

  -- Deliberately unrestricted models, deliberately no tools: used to show the
  -- tool grant doing the work rather than the controls.
  ('red-team', 'Red team harness', 'agent', array[]::text[], array['docs__search'])
on conflict (slug) do update
  set allowed_models = excluded.allowed_models,
      allowed_tools  = excluded.allowed_tools;

insert into budgets (scope, scope_id, window_secs, limit_tokens, hard)
values
  ('global',    null,         86400, 2000000, true),
  ('principal', 'demo-agent',  3600,   50000, true),
  ('principal', 'red-team',    3600,   10000, false)
on conflict (scope, coalesce(scope_id, '')) do update
  set window_secs  = excluded.window_secs,
      limit_tokens = excluded.limit_tokens,
      hard         = excluded.hard;
