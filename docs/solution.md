# 1 · Solution

## Overview

**Cogut** is an AI Control Layer built as a **gateway**. Users, apps and agents
point their LLM base URL and their MCP endpoint at it, and from then on every
interaction crosses four checkpoints (hooks):

| Hook | What is inspected |
|---|---|
| `prompt_in` | every message a user or agent sends to a model |
| `response_out` | every model answer, including streamed tokens |
| `tool_call` | every MCP tool call an agent makes |
| `tool_result` | every result an MCP server returns to the agent |

At each hook the gateway runs a **hybrid** pipeline driven by one central
**control catalog** (TOML):

1. **Deterministic tier** — regexes, Luhn checks, attack signatures, identity and
   model grants, budgets, runaway-agent limits. Runs on every request in
   microseconds (see [architecture](architecture.md)).
2. **Semantic tier** — an LLM judge (local Ollama model) that runs **only** when the
   deterministic tier flags the traffic (`escalate_when = "suspicious"`), so clean
   traffic pays nothing for AI.
3. **Decision** — allow, redact (rewrite the text and continue) or block, with a
   fail-closed default when a detector is unavailable.
4. **Audit** — every decision, with the control and the policy version behind it,
   is written to a SHA-256 hash-chained log in Postgres (Supabase). The SecOps
   console ([reporting](reporting.md)) reads it.

The catalog is versioned in the database and **hot-reloaded**: an upload is
validated, diffed, stored and live on every instance within 5 s, without a restart.
An invalid upload is rejected and the last good version keeps serving.

Beyond filtering, the gateway is also the **only MCP server agents see**: it
federates upstream MCP servers, pins tool definitions against rug-pulls, enforces
deny-by-default tool/table grants per identity, and lets an agent ask a human for
more access (approve/deny popup in the console).

## Implemented controls / guardrails

All controls live in [`policy/control-catalog.toml`](../policy/control-catalog.toml)
and [`policy/signatures.toml`](../policy/signatures.toml). Every deterministic
control and signature has red (must trip) and green (must stay quiet) test cases —
see [testing](testing.md).

### Deterministic — secrets (OWASP LLM02)

| Control | Default action | Severity |
|---|---|---|
| `secret.aws-access-key` | block | critical |
| `secret.private-key` | block | critical |
| `secret.bearer-token` | redact | high |
| `secret.github-token` | redact | critical |
| `secret.slack-token` | redact | high |
| `secret.google-api-key` | redact | high |
| `secret.llm-api-key` (OpenAI / Anthropic keys) | redact | critical |
| `secret.stripe-key` | redact | critical |
| `secret.password-assignment` (EN + PL) | redact | high |
| `secret.jwt` | redact | high |
| `secret.connection-string` | redact | critical |

### Deterministic — personal data (OWASP LLM02)

| Control | Default action | Severity |
|---|---|---|
| `pii.email` | redact | medium |
| `pii.iban` | redact | high |
| `pii.payment-card` (with Luhn verification) | redact | high |
| `pii.pesel` (Polish national ID) | redact | high |
| `pii.phone` | redact | medium |

### Deterministic — prompt injection and obfuscation (OWASP LLM01)

| Control | Default action | Severity |
|---|---|---|
| `injection.instruction-override` (EN + PL) | flag → semantic judge | medium |
| `injection.role-hijack` (DAN, developer mode…) | flag → semantic judge | medium |
| `injection.fake-delimiter` (`<\|im_start\|>`, `[INST]`…) | flag | high |
| `injection.agent-directive` (indirect injection in tool output) | flag | high |
| `obfuscation.invisible-unicode` (zero-width, bidi, tag chars) | flag | high |
| `obfuscation.encoded-payload` (long base64) | flag | low |
| `consumption.divergence-attack` ("repeat X forever") | flag | medium |
| `leak.system-prompt-request` (EN + PL, OWASP LLM07) | flag | medium |

### Deterministic — output handling and excessive agency (OWASP LLM05, LLM06)

| Control | Default action | Severity |
|---|---|---|
| `output.markdown-exfiltration` (data-carrying image URLs) | block | high |
| `output.script-injection` (XSS in output) | redact | high |
| `output.sql-injection` (in tool arguments) | block | high |
| `output.path-traversal` | block | high |
| `agency.destructive-command` (`rm -rf /`, `DROP DATABASE`, force push…) | block | critical |
| `agency.credential-access` (`~/.ssh`, `.aws/credentials`, `.env`…) | block | high |
| `exfiltration.known-endpoint` (pastebin, webhook.site, ngrok…) | flag → semantic judge | high |

### Deterministic — historical exploits on AI infrastructure (task §4.4)

| Control | Default action | Severity |
|---|---|---|
| `exploit.code-execution` (`os.system`, `subprocess`, `eval`…) | block | critical |
| `exploit.unsafe-deserialization` (`pickle.loads`, `torch.load`, `yaml.load`) | block | critical |
| `signature.AIS-0001` … `AIS-0010` — external signature feed (pickle checkpoints, unpinned `from_pretrained`, `trust_remote_code=True`, `allow_pickle=True`, joblib/dill loaders, `curl \| bash`, `--extra-index-url` dependency confusion, Keras `safe_mode=False`, shell metacharacters, base64-decode-and-execute) | block | high/critical |

### Semantic (AI-based) controls

| Control | Detector | Threshold | Runs when |
|---|---|---|---|
| `injection.prompt-guard` | `llm_judge` (Ollama) | 0.80 | a deterministic control flagged the traffic |
| `exfiltration.intent` | `llm_judge` (Ollama) | 0.75 | a deterministic control flagged the traffic |
| `pii.contextual` | `presidio` | 0.65 | ships **disabled** (sidecar not built yet) |

### Access, budget and resource governance

| Guardrail | Where |
|---|---|
| Per-identity API keys (SHA-256 hashed), unknown principal denied | `principals` table, `[mcp] unknown_principal` |
| Global model allow/deny list, narrowed per identity | `[models]`, `principals.allowed_models` |
| Deny-by-default MCP tool grants, human approval for requestable tools/tables | `principals`, `[resources.requestable]` |
| Token, USD, request-count and concurrency budgets per trailing window, scoped global / user / model; hard (block) or soft (record) | `budgets` table, `PUT /admin/budgets` |
| Per-model pricing for cost accounting (local chargeback or list price) | `[pricing]` |
| Runaway-agent limits: tool calls per window, identical calls, nesting depth | `[runaway]` |
| Risk score per identity: escalate everything past 1.0, refuse past 5.0 | `[risk]` |
| MCP tool pinning (sha256 of each tool definition) — blocks rug-pulls | `[[mcp.server]] pinned` |
| Database access: model sees schema + row count only, rows go to the user, redacted | `[resources]` |
| Streaming: redaction across split deltas, tail held back, answer retracted on block | gateway streaming proxy |

## Configuration

The full annotated sample is [`policy/control-catalog.toml`](../policy/control-catalog.toml).
What a security team can change:

| Setting | Effect |
|---|---|
| `profile = "permissive" \| "balanced" \| "strict"` | Default action and fail mode for every control that doesn't set its own — one line changes the strictness of the whole catalog. |
| `[defaults] on_detect`, `fail_mode` | `allow` / `flag` / `redact` / `block`; `open` / `closed` when a detector errors or times out. |
| per control: `action`, `severity`, `hooks`, `pattern`, `enabled` | Block vs redact vs flag, which boundaries it guards, switch off without deleting. |
| per semantic control: `threshold` (0–1), `timeout_ms`, `escalate_when = always \| suspicious \| never`, `fail_mode` | Adherence level of the AI judge and who pays for it. |
| `[models] allowed / denied` | Which LLMs may be reached at all (deny wins). |
| `[pricing."<model>"]` | USD per million input/output tokens for budgets and cost reports. |
| `[risk] window_secs, escalate_at, block_at` | How past behaviour tightens enforcement on an identity. |
| `[runaway] max_tool_calls, max_identical_calls, max_depth` | Loop and recursion limits for agents. |
| `[resources.grants]`, `[resources.requestable]`, `max_rows`, `statement_timeout_ms` | Which tables each identity may query, which need a human. |
| `[[mcp.server]] url, enabled, pinned` | Which upstream MCP servers exist and which tool definitions are approved. |
| `signatures.toml` (`source`, `version`, `[[signature]]`) | Externally managed attack-signature feed, versioned with the catalog. |
| `budgets` rows (`PUT /admin/budgets`) | `scope` (global / user / model), `window_secs`, `limit_tokens`, `limit_usd`, `limit_requests`, `limit_concurrency`, `hard` (block) or soft (record and allow). |

**How a change takes effect:** edit a control in the console (*Controls & policies*
→ pencil, or upload a `.toml`), or `POST /admin/policy`. The upload is compiled and
validated (unknown keys, bad regexes, out-of-range thresholds and duplicate ids are
rejected with the error), stored in `policy_versions` with a human-readable diff,
and every gateway instance switches to it within 5 s. Requests already in flight
finish under the version they started with; every audit event records the version
that decided it.
