-- Results produced after the request has left the latency-sensitive path.
-- They are separate from `detections`: an event's detections are committed
-- into its audit hash, so appending to them later would break the chain.
create table public.semantic_analyses (
  id           bigserial primary key,
  event_id     bigint not null unique references public.events (id) on delete cascade,
  completed_at timestamptz not null default now(),
  verdict      public.verdict not null,
  latency_us   bigint not null check (latency_us >= 0),
  -- One entry per evaluated control, including below-threshold scores and
  -- detector errors. This proves a clean analysis actually completed.
  results      jsonb not null default '[]'::jsonb,
  constraint semantic_analyses_results_array check (jsonb_typeof(results) = 'array')
);
create index semantic_analyses_completed_idx
  on public.semantic_analyses (completed_at desc);
create index semantic_analyses_incident_idx
  on public.semantic_analyses (verdict, completed_at desc)
  where verdict <> 'allow';
alter table public.semantic_analyses enable row level security;
-- The gateway's privileged connection is the only writer. The dashboard has
-- the same read-only access as it does for events and detections.
create policy "security team reads semantic analyses"
  on public.semantic_analyses for select to authenticated
  using (public.is_team_member());
