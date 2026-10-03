// AI Control Layer — security report.
//
// Data comes from report/data.json, written by `just report`. Layout lives here
// so it can change without recompiling anything.

#let data = json("data.json")

#let severity-colour(s) = {
  if s == "critical" { rgb("#b3261e") }
  else if s == "high" { rgb("#c25e00") }
  else if s == "medium" { rgb("#7a6000") }
  else { rgb("#4a4a4a") }
}

#set document(title: "AI Control Layer — Security Report")
#set page(
  paper: "a4",
  margin: (x: 2.2cm, y: 2cm),
  footer: context [
    #set text(8pt, fill: luma(110))
    AI Control Layer · generated #data.generated_at
    #h(1fr)
    #counter(page).display("1 / 1", both: true)
  ],
)
#set text(font: ("Helvetica", "Arial"), size: 10pt)
#set par(justify: false)
#show heading.where(level: 1): it => [
  #set text(16pt, weight: "bold")
  #block(above: 1.4em, below: 0.7em)[#it.body]
]
#show heading.where(level: 2): it => [
  #set text(11pt, weight: "bold")
  #block(above: 1.2em, below: 0.5em)[#it.body]
]
#show table.cell.where(y: 0): set text(weight: "bold", size: 9pt)
#set table(stroke: (x, y) => if y == 0 { (bottom: 0.6pt + luma(60)) } else { (bottom: 0.3pt + luma(205)) })

// ---------------------------------------------------------------- header

#block[
  #text(20pt, weight: "bold")[AI Control Layer]
  #linebreak()
  #text(12pt, fill: luma(90))[Security report · trailing #data.window_hours hours]
]

#v(0.3em)
#line(length: 100%, stroke: 0.6pt + luma(60))
#v(0.6em)

#grid(
  columns: (1fr, 1fr),
  text(9pt, fill: luma(90))[
    *Generated* #data.generated_at
  ],
  text(9pt, fill: luma(90))[
    *Policy version* #if data.policy_version != none { raw(data.policy_version.slice(0, 12)) } else { "none recorded" }
  ],
)

// ---------------------------------------------------------------- posture

= Posture

#let stat(label, value, tint: luma(245)) = block(
  fill: tint, inset: 10pt, radius: 3pt, width: 100%,
)[
  #text(18pt, weight: "bold")[#value]
  #linebreak()
  #text(8pt, fill: luma(90))[#upper(label)]
]

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 8pt,
  stat("interceptions", data.totals.events),
  stat("blocked", data.totals.blocked, tint: rgb("#fdeceb")),
  stat("redacted", data.totals.redacted, tint: rgb("#fff6e5")),
  stat("controls fired", data.totals.detections),
)

#v(0.6em)

#let block-rate = str(calc.round(
  if data.totals.events > 0 { data.totals.blocked / data.totals.events * 100 } else { 0.0 },
  digits: 1,
)) + "%"

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 8pt,
  stat("block rate", block-rate),
  stat("allowed", data.totals.allowed),
  stat("tokens", data.totals.tokens),
  stat("escalations", str(calc.round(data.latency.escalation_rate, digits: 1)) + "%"),
)

// ---------------------------------------------------------------- integrity

= Evidence integrity

#block(
  fill: if data.chain.intact { rgb("#eaf5ec") } else { rgb("#fdeceb") },
  inset: 11pt, radius: 3pt, width: 100%,
  stroke: 0.5pt + if data.chain.intact { rgb("#2e7d4f") } else { rgb("#b3261e") },
)[
  #if data.chain.intact [
    *Audit chain verified intact.* All #data.chain.events_checked events reproduce
    their stored hash, and each links to its predecessor. No record in this period
    has been edited, inserted or removed since it was written.
  ] else [
    *Audit chain broken.* Verification failed first at event
    #data.chain.first_broken. Records at or after that point cannot be trusted and
    the cause must be investigated before this report is relied upon.
  ]
]

#text(8pt, fill: luma(110))[
  Each event is hashed together with its predecessor's hash. Editing any field of
  any row breaks that row and orphans every row after it. Re-verify at any time
  with `just verify-audit`.
]

// ---------------------------------------------------------------- controls

= Controls fired

#if data.by_control.len() == 0 [
  _No control fired in this period._
] else [
  #table(
    columns: (auto, 1fr, auto, auto),
    align: (left, left, left, right),
    table.header[Severity][Control][Tier][Hits],
    ..data.by_control.map(c => (
      text(fill: severity-colour(c.severity))[#c.severity],
      raw(c.control_id),
      c.kind,
      str(c.hits),
    )).flatten()
  )
]

// ---------------------------------------------------------------- latency

= Performance

#table(
  columns: (1fr, auto, auto),
  align: (left, right, right),
  table.header[Tier][p50][p95],
  [Deterministic], [#data.latency.deterministic_p50_us µs], [#data.latency.deterministic_p95_us µs],
  [Semantic], [#data.latency.semantic_p50_us µs], [#data.latency.semantic_p95_us µs],
)

#v(0.4em)
#text(9pt)[
  The semantic tier ran on #calc.round(data.latency.escalation_rate, digits: 1)% of
  interceptions. The remainder were resolved by deterministic controls alone, at
  roughly a thousandth of the cost. That ratio is the hybrid architecture paying
  for itself; if it approaches 100%, the escalation thresholds need review.
]

// ---------------------------------------------------------------- budgets

= Budgets

#if data.budgets.len() == 0 [
  _No budgets configured._
] else [
  #table(
    columns: (auto, 1fr, auto, auto, auto),
    align: (left, left, right, right, left),
    table.header[Scope][Subject][Used][Limit][Enforcement],
    ..data.budgets.map(b => {
      let pct = if b.limit_tokens != none and b.limit_tokens > 0 {
        b.used_tokens / b.limit_tokens * 100
      } else { 0 }
      (
        b.scope,
        if b.scope_id != none { raw(b.scope_id) } else { [—] },
        text(fill: if pct > 90 { rgb("#b3261e") } else { black })[#b.used_tokens],
        if b.limit_tokens != none { str(b.limit_tokens) } else { [—] },
        if b.hard { [hard] } else { text(fill: luma(110))[soft] },
      )
    }).flatten()
  )
]

// ---------------------------------------------------------------- principals

= Callers

#if data.by_principal.len() == 0 [
  _No activity._
] else [
  #table(
    columns: (1fr, auto, auto, auto),
    align: (left, right, right, right),
    table.header[Principal][Interceptions][Blocked][Tokens],
    ..data.by_principal.map(p => (
      raw(p.slug), str(p.events), str(p.blocked), str(p.tokens),
    )).flatten()
  )
]

// ---------------------------------------------------------------- incidents

= Blocked interactions

#if data.incidents.len() == 0 [
  _Nothing was blocked in this period._
] else [
  #text(9pt, fill: luma(110))[
    Evidence excerpts are masked by design: the audit log records enough to
    identify a finding and never enough to reuse it.
  ]
  #v(0.4em)
  #table(
    columns: (auto, auto, 1fr, auto),
    align: (left, left, left, left),
    table.header[When][Hook][Control / evidence][Principal],
    ..data.incidents.map(i => (
      text(8pt)[#i.at],
      text(8pt)[#i.hook],
      [
        #text(8pt, fill: severity-colour(i.severity), weight: "bold")[#i.control_id]
        #linebreak()
        #text(7.5pt, fill: luma(110))[#i.evidence]
      ],
      text(8pt)[#if i.principal != none { i.principal } else { "—" }],
    )).flatten()
  )
]
