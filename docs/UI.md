# CloudGuard — Product UI

See `PRODUCT_SPEC.md` §4 for the underlying UX principle: don't overwhelm, prioritize, always answer WHAT/WHY/HOW BAD/HOW DO I FIX IT/DID THE FIX WORK.

---

## 1. Overview (Executive Dashboard)

One argument read top to bottom, not a wall of cards. Each step is the
precondition for the next:

```
Overview                            ✓ Assessed 31 Aug 01:51  [Scan now] [Reports]

┌───────────────────────┬────────────────────────────────────┐
│ SECURITY SCORE        │ POSTURE TREND                      │
│   72 / 100            │        ╭────                       │
│   Needs attention     │   ─────╯                           │
│   ↑ +7 · assessed …   │                                    │
└───────────────────────┴────────────────────────────────────┘

 Critical 0 │ High 1 │ Medium 1 │ Low 0 │ No verdict 3

 ASSESSMENT COVERAGE                       75%  · oldest reading 22h
 ✓ Network  ✓ Storage  ⚠ Identity

┌────────────────────────┬────────────────────────────────────┐
│ PRIORITY RISKS         │ SHORTEST ATTACK PATH               │
│ ① Public database  94  │ vm-jump-01 → prodstorage           │
│   Internet-facing      │ ① runs as mi-jump                  │
│   Sensitive data       │ ✂ can act over prodstorage         │
└────────────────────────┴────────────────────────────────────┘

┌────────────────────────┬────────────────────────────────────┐
│ REMEDIATION            │ RECENT CHANGES                     │
│ 34% verified fixed     │ ↑ exposure · storage-prod    2h    │
└────────────────────────┴────────────────────────────────────┘
```

**The order is the argument.** Where the posture stands and which way it moves;
what that number is made of; how much of the estate the opinion was formed from;
what to deal with and what those faults form *together*; whether any of it is
getting fixed; what moved while you were away.

Coverage sits third on purpose — a score computed over half an environment is a
different claim from the same number over all of it, and a reader who has
already acted on the risks below has been told too late. It is never phrased as
a security percentage: 75% coverage is the share of checks that reached a
verdict, not 75% secure.

**UNKNOWN sits in the severity strip**, at the end and labelled "no verdict". It
is not a fifth severity and it is never a pass, but a reader tallying what is
wrong has to see what could not be answered in the same glance.

**A ranked risk carries the terms it was ranked by** — internet-facing,
sensitive data, business-critical — so a rank reads as a reason rather than as
an assertion. A scenario is marked as a route, because it groups findings that
are already counted individually.

**The charts follow the question, not the variety.** Rings only where the data
is a whole divided in two or three (coverage; finding status); severity as one
stacked bar; risk bands and framework coverage as bars from a common baseline;
the trend as an area on a fixed 0–100 scale with the score bands painted behind
it; a treemap on the Assets hierarchy, the one place area is the right encoding.
Sparklines under each severity count and beside the attack-path panel come from
posture history the payload already carried. No dual axes anywhere. Motion
counts numbers up when they change, animates a chart once on mount, and honours
`prefers-reduced-motion` by arriving rather than crawling.

**Inventory counts are not headline figures here.** Assets, subscriptions and
resources are true and answer a different question; every pixel one takes is a
pixel not spent on what is wrong.

**Nothing is scored before a scan exists.** The empty state offers the first
scan and shows no number at all — a score over no evidence is a number about
nothing, and a reassuring one is worse.

---

## 2. Technical Dashboard — Navigation

A left sidebar, grouped by the question each screen answers rather than by the
order the pages were built (`components/layout/nav.ts`):

```
Posture    Overview  Changes  Reports
Exposure   Findings  Risks  Attack paths  Assets
Response   Remediation  Compliance
Evidence   Scans  Rules  Cloud  Settings
```

It collapses to an icon rail, remembered per browser, because sixty pixels of
label per row is a good trade on a wide monitor and a bad one on a small laptop.
The rail keeps the grouping and the order and gives up only the words; every
icon still names itself on hover and to a screen reader. Below `lg` the same
navigation is a sheet behind the header's menu button.

Detail screens carry a breadcrumb rather than a lone back button — what this is
a detail *of*, then what it is called — so somebody arriving from a shared link
knows where they are, not only where to leave.

---

## 3. Key Pages

**Assets** — resource, type, environment, region, criticality, exposure, findings count, last seen; filterable by type/environment/criticality/exposure/risk. Two readings of one inventory, switched in the header. **List** is the queue: assets with open findings first, filterable, paged, groupable by resource group, type or environment. **Hierarchy** is the estate's shape — subscription → resource group, counted server-side over the whole estate and ordered worst first at both levels, with a group expanding to what is in it. The tree is what leads from a number to an owner, since a resource group usually has one; opening a group in the list carries the scope as a filter chip that can be taken off. Assets sitting directly in a subscription are named as that, not as "Ungrouped".

**Findings** — finding, severity, asset, risk, status, first/last seen; filterable by severity/status/rule and free text, searched and ordered in the database rather than in the browser. Severity, risk score and last seen order from their own column headers, one direction each: worst risk, worst severity and most recent all mean descending, and an ascending security queue puts the least urgent row first.

**Remediation** — the work queue, ordered by impact against effort. Work reaches it from a finding's recommended fix (`DECISIONS.md` §41). Each row names the finding and the asset it is on, joined in the browser because the endpoint returns only the task (`DECISIONS.md` §29). Marking work done does not close a finding — a scan does — and the answer says so where the button is.

**Finding detail** — title, severity, asset, why it matters, evidence, risk score, recommended fix, estimated effort, owner, and actions: **Assign / Mark In Progress / Accept Risk / Rescan**. It also says what the finding is *part of*: the attack paths its asset sits on, drawn as routes with the link worth cutting marked, and labelled by where the asset sits on each — the way in, a link in the middle, or the target. No route found is written as a fact about the graph rather than as reassurance, because what counts as sensitive is something the customer declares. Evidence is the raw capture, clipped past about two screens with the rest one click away and copyable whole.

**Finding detail — how we know.** Under the evidence excerpt, the readings that
excerpt came from: which listing, how long ago the *provider* was read, the
permission the read was made under, and whether the capture is still stored. The
excerpt says what the rule saw; this says where it came from, which is the
difference between a claim a customer accepts and one they check. Three answers
are kept apart that a careless rendering would flatten into one blank space —
"raised before CloudGuard recorded this" is a fact about the product, "this
check reads no collected evidence" is a fact about the rule, and a failed
request is neither, so the panel does not render at all. Age is the API's
number, not the browser's: a carried reading is older than the scan that raised
the finding, and a clock-side calculation would differ per machine.

**Scan — what rested on a reading.** Each listing in a scan's collection panel
says when the provider was read and how many findings rest on it, linking to
exactly those. The finding page asks where its evidence came from; this is the
same chain from the evidence end, which is the question somebody looking at a
failed or stale listing actually has. A reading that failed says *no findings
rest on this* and is not a link — the rules that needed it degraded to UNKNOWN
and never became findings, which is the engine working rather than a gap. The
link carries `status=all`, because a reading whose findings have since been
fixed would otherwise land on an empty table and read as "nothing rested on it".

**Rules** — the catalogue, filterable by severity and free text. It lists what CloudGuard *runs*: a rule withdrawn from the registry (`enabled: false`) is held back behind a toggle and named as withdrawn, because it no longer runs and compliance coverage no longer counts it. Each rule expands to its rationale and the fix in every form the backend holds — prose, CLI, Terraform, Azure Policy.

**Risk detail** — the findings a risk was built from, each one openable, plus the arithmetic in the terms that score was actually built from: the six weighted components for a finding risk, or worst-member/amplifier/hops for a route. The two are never mixed — a scenario was not scored from criticality and exploitability, so it is not shown them.

**Settings** — the half of the evidence a person supplies. The organization profile (name, industry, country; the slug is shown and never editable, because a rename must not change an identifier already in stored references). Per-subscription **context declarations** — environment, criticality, data sensitivity, note — which are what the risk engine multiplies every finding by, and which beat anything inferred from a tag or a resource name. `UNKNOWN` is not offered: it is CloudGuard's word for "nothing said anything", so leaving a field unset withdraws a claim rather than declaring the value unknown. A declaration applies at the next evaluation, not retroactively. Deletion lives here too, gated on typing the organization name, and offered to owners only.

**Reports** — two generated documents, with an **activity window** (30/90/365 days, which moves the verified-fix and completed-work counts and the trend line but never the posture) and per-section tickboxes (top risks, attack paths, remediation progress, compliance coverage, and — technical only — the full findings list). Anything unticked is named on the report's cover as excluded, so a reader downstream can tell a choice from a gap; the posture and the evidence caveats cannot be switched off. The two documents: **Executive** (posture, a fixed-scale 0–100 score sparkline, top risks, compliance coverage — no findings list) and **Technical** (the same numbers, then every open finding worst first). Both offer a PDF download and an HTML preview of the same document. Nothing is stored: reports are generated on request, and the page says so. Fetched with the caller's token rather than linked, because the bearer token lives in memory and a plain anchor would arrive unauthenticated.

**Changes** — what moved in the environment, newest first, grouped by the day it was observed; filterable by window (24 hours / 7 / 30 / 90 days) and by kind. Rows say whether an attribute change went up or down; a move into UNKNOWN is neither. A `DISAPPEARED` row says whether the asset is missing *now*, which is what makes it a job rather than history.

**Scan** — **automatic scanning** per connection (an interval, off by default). It is set here rather than on the connection card: this page answers when the environment was last read and when it will be read next, and a schedule is the second half of that sentence. Then live progress (discovery → rules → risk analysis) then a summary: resources, rules run, findings by severity. A finished run also offers **Re-evaluate**, which runs today's rules against the capture it already stored — no Azure call. A replay labels itself as one, and says which of the two things its counts mean: applied to the current picture (findings moved), or advisory (the capture has been superseded, so nothing was created, resolved or reopened).

**Connection card** — per connection: the two grants, discovered subscriptions and their scope, a line naming where automatic scanning is now set and what it is set to, and **React to changes** (opens CloudGuard's webhook and hands over the `az eventgrid` command per subscription). The change control has to say that turning it on wires nothing up: creating that subscription is a write in the customer's tenant, and CloudGuard holds no write permission anywhere.

---

## 4. Colour

Two layers, and the separation is load-bearing. The **semantic tokens** —
`background`, `card`, `muted`, `border`, `ring`, `primary`, `destructive` — are
the product's chrome and may be re-themed. The **severity scale** —
`critical`, `high`, `medium`, `low`, `unknown`, `ok`, each with a `-bg` tint and
a `-border` — is what a colour *means* to somebody reading a security finding,
and must not drift when an accent changes. `destructive` means "this button
deletes something"; `critical` means "an attacker can reach your data".
Collapsing the two would paint a cancel button and a public storage account the
same colour.

Both live in `apps/web/src/index.css` as Tailwind 4 `@theme inline` (there is no
`tailwind.config.js`; `DECISIONS.md` §35 covers why v3 cannot be gone back to).
Components use the tokens, never a raw hex or a Tailwind palette class — a
`bg-stone-50` is a light-mode decision written into a component, and it does not
flip when the theme does.

**Every pair is contrast-checked in both modes.** Text clears 4.5:1 against the
surface it sits on; chart series and the focus ring clear 3:1. The theme is a
class on `<html>` set before React exists, so "system" is a real third choice
rather than a synonym for light.

Three things that follow from this and are easy to get wrong:

- **Each mode is lit from its own surface.** The dark severity backgrounds are
  tints of the dark surface, not of white — a light tint on a dark page glows,
  and a glowing badge reads as more urgent than the one beside it, which is a
  ranking the rules never made. The neutral chart ramp likewise runs light-to-
  dark on the light page and dark-to-light on the dark one; it used to be one
  ramp copied into both blocks, which left roughly half of it invisible in each.
- **Hue is reserved for severity.** The chart ramp is deliberately neutral: a
  chart that coloured its series would be making a claim the rules never made.
  For the same reason there is no saturated accent anywhere in the chrome.
- **UNKNOWN gets its own colour and a dashed border**, not a shade of LOW — a gap
  in knowledge is not a mild problem, and the dash keeps it distinguishable
  without relying on colour at all.

---

## 5. Onboarding

See `AZURE_INTEGRATION.md` §3 for the full onboarding flow and the connection-screen copy.
