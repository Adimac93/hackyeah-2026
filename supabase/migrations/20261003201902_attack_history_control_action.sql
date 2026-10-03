-- attack_history records what a *control* did, and a control can `flag`.
-- The column was typed as `verdict` (allow/redact/block — a request's fate),
-- so every flagged detection failed to insert. That aborted the audit
-- transaction, which rolled back the event itself and left a gap in the hash
-- chain. Type it as `control_action`, the enum detections already use.
alter table public.attack_history
  alter column action type control_action using action::text::control_action;
