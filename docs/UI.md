# CloudGuard — Product UI

See `PRODUCT_SPEC.md` §4 for the underlying UX principle: don't overwhelm, prioritize, always answer WHAT/WHY/HOW BAD/HOW DO I FIX IT/DID THE FIX WORK.

---

## 1. Executive Dashboard

```
+------------------------------------------------+
|  Security Posture                               |
|        84 / 100     (+7 since last scan)       |
+------------------------------------------------+
 Critical  1     High  4     Medium  13
 Top Risk: Production database publicly accessible
 Remediation: 78% of high-risk items resolved
```

Read top to bottom the overview is one argument: the score and which way it is
moving, what it is made of, how much of the environment CloudGuard could
actually see while forming the opinion, then the specific things to go and do
about it — ranked risks (each linking to that risk, not back to the list),
the shortest attack paths with the hop worth cutting, and what moved in the
last seven days. The last two are asked for small and fail quietly: a dashboard
that cannot draw its final panel is still a dashboard.

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

**Remediation** — the work queue, ordered by impact against effort. Each row names the finding and the asset it is on, joined in the browser because the endpoint returns only the task (`DECISIONS.md` §29). Marking work done does not close a finding — a scan does — and the answer says so where the button is.

**Finding detail** — title, severity, asset, why it matters, evidence, risk score, recommended fix, estimated effort, owner, and actions: **Assign / Mark In Progress / Accept Risk / Rescan**. It also says what the finding is *part of*: the attack paths its asset sits on, drawn as routes with the link worth cutting marked, and labelled by where the asset sits on each — the way in, a link in the middle, or the target. No route found is written as a fact about the graph rather than as reassurance, because what counts as sensitive is something the customer declares. Evidence is the raw capture, clipped past about two screens with the rest one click away and copyable whole.

**Rules** — the catalogue, filterable by severity and free text. It lists what CloudGuard *runs*: a rule withdrawn from the registry (`enabled: false`) is held back behind a toggle and named as withdrawn, because it no longer runs and compliance coverage no longer counts it. Each rule expands to its rationale and the fix in every form the backend holds — prose, CLI, Terraform, Azure Policy.

**Risk detail** — the findings a risk was built from, each one openable, plus the arithmetic in the terms that score was actually built from: the six weighted components for a finding risk, or worst-member/amplifier/hops for a route. The two are never mixed — a scenario was not scored from criticality and exploitability, so it is not shown them.

**Settings** — the half of the evidence a person supplies. The organization profile (name, industry, country; the slug is shown and never editable, because a rename must not change an identifier already in stored references). Per-subscription **context declarations** — environment, criticality, data sensitivity, note — which are what the risk engine multiplies every finding by, and which beat anything inferred from a tag or a resource name. `UNKNOWN` is not offered: it is CloudGuard's word for "nothing said anything", so leaving a field unset withdraws a claim rather than declaring the value unknown. A declaration applies at the next evaluation, not retroactively. Deletion lives here too, gated on typing the organization name, and offered to owners only.

**Reports** — two generated documents, with an **activity window** (30/90/365 days, which moves the verified-fix and completed-work counts and the trend line but never the posture) and per-section tickboxes (top risks, attack paths, remediation progress, compliance coverage, and — technical only — the full findings list). Anything unticked is named on the report's cover as excluded, so a reader downstream can tell a choice from a gap; the posture and the evidence caveats cannot be switched off. The two documents: **Executive** (posture, a fixed-scale 0–100 score sparkline, top risks, compliance coverage — no findings list) and **Technical** (the same numbers, then every open finding worst first). Both offer a PDF download and an HTML preview of the same document. Nothing is stored: reports are generated on request, and the page says so. Fetched with the caller's token rather than linked, because the bearer token lives in memory and a plain anchor would arrive unauthenticated.

**Changes** — what moved in the environment, newest first, grouped by the day it was observed; filterable by window (24 hours / 7 / 30 / 90 days) and by kind. Rows say whether an attribute change went up or down; a move into UNKNOWN is neither. A `DISAPPEARED` row says whether the asset is missing *now*, which is what makes it a job rather than history.

**Scan** — live progress (discovery → rules → risk analysis) then a summary: resources, rules run, findings by severity. A finished run also offers **Re-evaluate**, which runs today's rules against the capture it already stored — no Azure call. A replay labels itself as one, and says which of the two things its counts mean: applied to the current picture (findings moved), or advisory (the capture has been superseded, so nothing was created, resolved or reopened).

**Connection card** — per connection: the two grants, discovered subscriptions and their scope, **Automatic scanning** (an interval, off by default), and **React to changes** (opens CloudGuard's webhook and hands over the `az eventgrid` command per subscription). The change control has to say that turning it on wires nothing up: creating that subscription is a write in the customer's tenant, and CloudGuard holds no write permission anywhere.

---

## 4. Onboarding

See `AZURE_INTEGRATION.md` §3 for the full onboarding flow and the connection-screen copy.
