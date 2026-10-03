# Prior art

Landscape survey for the AI Control Layer challenge (`docs/task.md`), as of **2026-10-03**.
Purpose: know what exists before we build, cite it in the §3.1b architecture diagram, and
aim our effort at the parts nobody covers.

Short version: the category is crowded, nothing matches the brief end to end, and the
65% of the score that judges weight most heavily sits on things no existing gateway
hands you.

## Closest matches

| tool | lang / license | covers | gap vs `task.md` |
|---|---|---|---|
| [agentgateway](https://github.com/agentgateway/agentgateway) — Linux Foundation, 5.1k★ | Rust, Apache-2.0 | **Closest single match.** Proxies all three channels the brief names — agent↔LLM, agent↔MCP, agent↔agent. CEL policy engine + RBAC, JWT/OAuth/API keys, regex guardrails, token budgets and spend controls, OpenTelemetry, dashboard | semantic guardrails are delegated to **paid** services (OpenAI moderation, AWS Bedrock Guardrails, Google Model Armor) — unusable under §7, which provides no paid subscriptions. No attack-signature feed. No test suite |
| [ContextForge / IBM mcp-context-forge](https://github.com/IBM/mcp-context-forge) — 4.6k★ | Python + Rust, Apache-2.0 | MCP / A2A / REST federation behind one endpoint, virtual servers as tool filtering, 40+ plugins, admin dashboard with live log viewer, rate limiting, SSRF protection and domain allowlists, OAuth/JWT/SSO | LLM side is thin: token *tracking* via OTel, not budget *enforcement*. No semantic guardrails |
| [Bifrost](https://github.com/maximhq/bifrost) — 8.5k★ | Go, Apache-2.0 | Best budget model of the four: hierarchical dollar budgets across four nesting levels (virtual key → team → customer), rate limits, MCP, Ollama provider, dashboard, plugin system | open-core — guardrails are the paid pitch. Caveat: most "best AI gateway 2026" listicles are published by Maxim, Bifrost's own vendor. Discount accordingly |
| [LiteLLM](https://github.com/BerriAI/litellm) | Python, MIT | de-facto spend layer — internal cost DB for all supported models, real-time spend per virtual key / user / team / project | not a security layer at all |

Also seen but not evaluated in depth: Microsoft MCP Gateway (k8s reverse proxy, session-aware
routing), MCPX (tool-level RBAC, immutable audit trails), Lasso mcp-gateway, Enkrypt AI.

**[mcpm.sh](https://mcpm.sh/)** is *not* in this category despite the name overlap — it is a
package manager for MCP servers. Its v1 "Router" did sit in the request path; v2 removed it in
favour of profiles. Useful only as demo furniture: `mcpm install` provisions a realistic fleet
of MCP servers for our layer to sit in front of, and its registry is a plausible source for a
known-server allowlist (§4.4 supply chain).

## Guardrail components

Reuse these; they are components, not architecture.

- **[Llama Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)** —
  injection/jailbreak classifier. 86M (mDeBERTa-base) and 22M (DeBERTa-xsmall) variants; the
  22M cuts latency ~75% and runs on CPU. Our semantic layer's default.
- **[Presidio](https://pypi.org/project/presidio-analyzer/)** — PII detection/anonymisation.
  Moved out of Microsoft to a community org; runs fully local, optionally LLM-backed via Ollama.
  Needs spaCy `en_core_web_lg`.
- **NeMo Guardrails** (NVIDIA) — Colang dialogue policy; calls Presidio underneath for PII.
  Heavier than we need, but the reference for multi-turn policy.
- **Guardrails AI** — output schema validation. Relevant only if we enforce structured output.
- **[LlamaFirewall](https://arxiv.org/pdf/2505.03574)** (Meta) — open-source guardrail system
  for agents. Same thesis as our brief. Read before finalising the architecture.

### Dead end: LLM Guard

[protectai/llm-guard](https://github.com/protectai/llm-guard) was **archived 2026-07-09** and
is read-only. 15 input scanners, 20+ output scanners, MIT, and the code still runs — but a
security component that receives no updates against new attack patterns is a liability, and
roughly half the 2026 comparison articles still recommend it. Do not build the semantic layer
on it. Expect a judge to know this.

### Known weakness to design around

Classifier evasion against exactly these defenses is well documented:
[arXiv 2504.11168](https://arxiv.org/pdf/2504.11168) (evasion attacks on injection/jailbreak
detectors) and [arXiv 2510.01529](https://arxiv.org/pdf/2510.01529) (controlled-release
prompting bypasses production prompt guards). Reported F1 for small classifiers such as
Prompt Guard 2 lands around 0.35 on some benchmarks. A defense that is only a classifier
loses points on "Robustness of the Solution and Quality of Guardrails" — the 30% criterion.
Defense in depth, and being explicit about known misses, scores better than claiming coverage.

## Where the gaps are — our scoring surface

Four requirements in the brief that nothing above satisfies:

1. **§4.4 historical attack mitigation from an external signature feed.** No gateway does
   CVE/signature-driven blocking for AI infrastructure — unsafe pickle deserialization,
   malicious model repositories, supply-chain exploits. The most differentiating requirement
   in the brief, and the least contested.
2. **Live reconfiguration.** §6 states judges *will* modify config files to see how the layer
   adapts. Most of these tools need a restart. Hot-reload with a visible diff in the dashboard
   is cheap to build and directly demoable.
3. **§4.6 self-testing suite as a first-class deliverable.** No gateway ships one. 15% of the
   score, and it is the artifact judges actually execute.
4. **Hybrid routing under the no-paid-API constraint.** agentgateway punts semantics to paid
   APIs; §7 forbids that. Deterministic checks first, escalating to a local Ollama /
   Prompt Guard 2 classifier only on suspicion, with per-stage latency telemetry, is a genuine
   architectural contribution rather than a reimplementation — and §6 says performance
   telemetry may be used in evaluation.

## Decision

**Do not fork a gateway.** Build the proxy thin; own the policy engine, the signature feed,
the dashboard, and the test suite. Borrow components, not architecture — Presidio for PII,
Prompt Guard 2 for injection, LiteLLM's cost tables for pricing data.

Rationale against the published weights: guardrails 30% + security reporting 20% + test suite
15% = **65% of the score rests on what no gateway provides**. Forking agentgateway spends the
clock learning its CEL plugin API, and a judge sees configuration rather than engineering.
Architecture is a further 20% and rewards our own design.

Cite these four as considered prior art in the architecture diagram. One box, and it buys
credibility for the parts we did build.
