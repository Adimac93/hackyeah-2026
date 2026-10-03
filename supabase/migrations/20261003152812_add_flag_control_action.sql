-- A control may fire without changing the request's fate: `flag` records the
-- detection and lets the call through. That is how a cheap deterministic
-- control marks traffic as suspicious so the semantic tier knows to look,
-- which is the mechanism that keeps p50 latency low.
--
-- `events.verdict` keeps the three outcomes a caller can observe
-- (allow/redact/block); only a detection can be a flag.

create type control_action as enum ('allow', 'flag', 'redact', 'block');

alter table detections
  alter column action type control_action
  using action::text::control_action;
