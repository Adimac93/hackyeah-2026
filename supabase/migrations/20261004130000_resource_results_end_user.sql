-- Query results belong to the end user who asked, not only to the identity
-- that called. A delegating identity (the console chat) acts for many users;
-- keyed by identity alone, any of them could fetch the others' rows.
-- `resources__query` stores `principals.user` (the X-On-Behalf-Of user, or
-- the identity's own slug) and `GET /v1/results/{id}` matches on both.
--
-- Rows from before this column have no owner and stay unreadable; they
-- expire within the hour anyway.
alter table public.resource_results add column end_user text;

drop index if exists public.resource_results_principal_idx;
create index resource_results_owner_idx
  on public.resource_results (principal_id, end_user, created_at desc);
