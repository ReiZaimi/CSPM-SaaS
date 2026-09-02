# CloudGuard — API Design

## 1. Endpoints

Every path below is prefixed `/api/v1`. This list is generated from the routers
under `app/api/routes/` — if it disagrees with them, they are right.

```
POST   /organizations                      GET    /organizations
GET    /organizations/{id}                 PATCH  /organizations
DELETE /organizations/{id}

POST   /cloud-connections                  GET    /cloud-connections
GET    /cloud-connections/{id}             DELETE /cloud-connections/{id}
POST   /cloud-connections/{id}/discover
PATCH  /cloud-connections/{id}/subscriptions
PATCH  /cloud-connections/{id}/schedule
GET    /cloud-connections/{id}/change-events
PATCH  /cloud-connections/{id}/change-events
POST   /cloud-connections/{id}/cancel      POST   /cloud-connections/{id}/resume
GET    /cloud-connections/{id}/revocation
POST   /cloud-connections/{id}/check-revoked
GET    /cloud-connections/azure/app-registration
GET    /cloud-connections/{id}/template            (unauthenticated, CORS-open)
GET    /cloud-connections/azure/consent/callback   (unauthenticated, signed state)

POST   /events/azure/{connection_id}               (unauthenticated, signed token)

GET    /cloud-accounts                     GET    /cloud-accounts/{id}
GET    /cloud-accounts/azure/permissions
GET    /cloud-accounts/{id}/context
PUT    /cloud-accounts/{id}/context
DELETE /cloud-accounts/{id}/context

POST   /scans                              GET    /scans
GET    /scans/{id}                         DELETE /scans/{id}
GET    /scans/{id}/detail                  GET    /scans/{id}/coverage
GET    /scans/{id}/collection
POST   /scans/{id}/replay                  POST   /scans/{id}/cancel
GET    /scans/worker-status

GET    /assets                             GET    /assets/{id}
GET    /assets/hierarchy
GET    /changes
GET    /findings                           GET    /findings/{id}
GET    /risks                              GET    /risks/{id}

POST   /remediation                        GET    /remediation
PATCH  /remediation/{id}
POST   /findings/{id}/accept-risk          POST   /findings/{id}/status
POST   /findings/{id}/rescan
GET    /findings/{id}/attack-paths         GET    /findings/{id}/provenance

GET    /attack-paths                       GET    /attack-paths/choke-points
GET    /attack-paths/blast-radius/{resource_id}

GET    /rules                              GET    /rules/{rule_id}
GET    /compliance                         GET    /compliance/{framework_id}

GET    /notifications                      POST   /notifications/read

GET    /dashboard
GET    /reports/{kind}?format=pdf|html&days=30&sections=a,b
```

Three of the scan endpoints exist because a scan is resumable work rather than
one call. `/detail` is the run's steps; `/coverage` is what each rule reached a
verdict on and what it could not; `/collection` is which evidence key arrived and
which did not, which is the row that makes an UNKNOWN answerable rather than
merely reported. `/replay` re-runs today's rules against a capture already
stored — no Azure call — and `/worker-status` pings the broker, because "scans
stay queued" is otherwise indistinguishable from "the product is broken".

`POST /findings/{id}/status` is the general transition; `accept-risk` is its own
endpoint rather than a status value because it takes a reason and an approver.

`/cloud-accounts` is **read-only** except for `/context`: an account is a
subscription discovered beneath a connection, so there is nothing to create,
consent to, or validate there. Scoping one in or out is a PATCH on its
connection, not a delete — a deleted row would return on the next discovery run.

`/context` is the exception, and a principled one: everything else about a cloud
account records what Azure said, while a declaration records what a *person*
said. A customer marking a subscription production beats any amount of tag
inference, and there was previously nowhere to put the answer. The PUT replaces
the whole declaration rather than patching it — a field left out is one the
customer is no longer claiming, and a body claiming nothing withdraws the
declaration entirely, exactly as DELETE does. `UNKNOWN` is rejected for either
level: it is CloudGuard's own answer for "nothing said anything", so declaring
it would be asserting an absence that leaving the field out already asserts.

A declaration is applied by the next evaluation of the subscription — the next
scan, or a replay of its latest capture — and never rescores stored findings on
the spot. A risk score is what a scan concluded, and rewriting one from an API
call would leave findings carrying numbers no observation ever produced. It is
also applied as a *floor*: it can raise an asset's criticality above what the
capture supported but never lower it, so the worst a mistaken declaration can
do is over-rank something. `GET /assets/{id}` returns a `context` block giving
each value's source and confidence alongside it.

Three endpoints are unauthenticated by necessity, all protected by an
HMAC-signed token rather than a session: `/cloud-connections/azure/consent/callback`,
which Entra's redirect reaches from the customer's browser;
`/cloud-connections/{id}/template`, which Azure Portal fetches *from the
customer's browser* for the Deploy to Azure button — the reason it is also the
one endpoint answering `Access-Control-Allow-Origin: *`; and
`/events/azure/{connection_id}`, which Azure Event Grid delivers to when their
environment changes. All three are `include_in_schema=False`: they are reached
by Azure and by browsers following a link, never by this product's client, and
listing them in the OpenAPI document would invite a consumer to call them.

The webhook is separated from the template token by the `purpose` claim, not by
the signature — both are signed with the same secret, so it checks the claim
rather than treating a valid signature as proof of intent.

`/cloud-connections/{id}/change-events` returns the commands the customer runs
to wire their subscriptions up. CloudGuard cannot create the Event Grid
subscription itself: that is a write in their tenant, and it holds no write
permission anywhere. An event does not start a scan directly — a burst marks the
connection, the scan waits for the environment to go quiet, and a floor stops an
afternoon of deployments becoming an afternoon of scans.

`/rules/{rule_id}` and `/findings/{id}` carry `remediation_spec` beside the
remediation prose: the settings that must be true for the finding to close, the
CLI commands that set them, the Terraform arguments for whoever manages this in
code, and — only where one can genuinely enforce the whole rule — a generated
Azure Policy definition. `enforceable: false` with `azure_policy: null` is a
fact about the check rather than missing work: whether an administrator has MFA
is a directory setting, and no `policyRule` can express it. A rule with no
declaration at all returns `remediation_spec: null`; every rule in the current
set has one, so that answer is reserved for a rule added without one.

Each expected state carries its `comparison` — `equals`, `none_matching` or
`not_empty` — because without it a collection expectation serializes as
`equals: null`, which reads as "this must be null" rather than "this must not be
empty". A collection expectation also carries an `example`: the rule shape that
must not exist, or an entry that satisfies. Two rules report an empty
`expected_state` with a `notes` field explaining why — one judges a ratio across
the directory, the other a relationship between two assets — rather than
inventing a per-asset setting to point at.

`/notifications` is deliberately not `/changes`. That answers "what moved in the
environment" and is a property of the estate; this answers "what happened since
you last looked" and is a property of a reader — the same scan gives everyone
the same changes and each person a different unread count. Three kinds only:
a new finding on an asset that stands on an attack path, a fix a scan verified,
and a reading that stopped arriving. Severity alone is not a reason: a CRITICAL
on an isolated sandbox is a rulebook event, and a bell that fired on every
finding would be a filter rule inside a fortnight.

`meta.unread` and the list come from one read of the same rows, so a badge
cannot say three above a panel showing two. `POST /notifications/read` moves the
caller's watermark to *now* rather than to the newest stored row — the sweep
runs on a timer, and reading to the newest row would mark something seen before
it was written. Rows are derived by a periodic job from `finding_events`,
`evidence` and the graph, never written by the scanner: one source of truth
about what happened, and a replay generates nothing because it writes no finding
events.

`/dashboard` carries two figures that are easy to confuse and answer different
questions. `coverage` is the share of checks that reached a verdict;
`evidence_freshness` is how recently the provider was actually read, measured
over the newest reading of each scope and evidence key rather than from the last
scan's finish time — a scan may carry a reading forward instead of re-taking it,
and a carried reading keeps the time it was collected. The headline is the
*oldest* of those readings, because an average would let a hundred fresh
listings hide the one subscription nobody has managed to read since Tuesday.

`/assets` returns `provider_resource_id` on every row, not only on the detail.
It is the one field that says where an asset *sits*: an ARM id spells out its
own subscription and resource group, so a client can group an inventory by scope
without a request per row. The row `id` is a CloudGuard identifier and names
nothing in the customer's cloud — the ARM id is what they can search for in
their own portal.

`/findings` also takes `evidence_id` — the citation chain walked from the other
end. `/scans/{id}/collection` reports how many findings rest on each reading, and
this is what that count links to. Filtered on the reading rather than on its
evidence key, because a key spans every subscription and every scan that ever
read it: the number offered and the rows returned have to be the same set, or it
is a count that does not survive being clicked.

`/findings` takes `search` and `sort` (`risk` by default, or `severity` or
`recent`), and `/risks` takes `search`. Both are on the server rather than left
to the client for the same reason: these endpoints paginate, so a client that
searched or ordered the page it was handed would be searching a hundred rows of
an estate and reporting "nothing matches" for the rest. `sort=severity` ranks
CRITICAL first rather than alphabetically, and an unrecognised `sort` is
rejected with 422 rather than quietly falling back to a different order than the
one asked for. `search` matches a finding's title, its rule id, or the name of
the resource it was found on; for a risk, its title or description.

`/changes` answers "what moved while I was away": asset appearances,
disappearances, and changes to the three attributes the risk engine multiplies a
finding by. A feed of transitions rather than a diff of two scans, so a week in
which nothing changed returns nothing rather than restating the inventory. The
window defaults to seven days and is bounded at ninety. `GET /findings/{id}`
carries the matching per-finding view as `timeline`, which is where a
regression becomes visible: a finding raised, fixed and raised again is
indistinguishable from one raised and fixed once if all you have is
`first_detected_at` and `resolved_at`.

Marking a remediation task `DONE` opens a **verification**: CloudGuard records
what it now expects to see and checks the environment on a backoff (5m, 15m, 1h,
4h) until it can answer. `GET /findings/{id}` returns that answer under
`verification`, and its `detail` is written for a person, because "still
failing", "CloudGuard could not read enough to tell" and "too soon, checking
again" are the same open finding and three different pieces of news. Cancelling
the task, or accepting the risk, withdraws the question rather than leaving it
pending.

`/assets/hierarchy` returns the estate as it is organised — subscriptions (and
the directory, which belongs to no subscription) each holding their resource
groups, with asset and open-finding counts at both levels, worst first. The
resource group is read out of the ARM id's fifth segment in the database rather
than stored: an id states its own subscription and group, and a stored copy is
one more thing to keep in step. Directory assets are named as such rather than
reported as assets whose subscription is unknown.

Counted over the whole estate and returned whole, unlike `/assets`, which pages.
A tree built from one page of a paginated list would show a resource group once
per page its assets straddled, each time with a fraction of its findings.

`/assets` accordingly takes `subscription_id` and `resource_group` so the tree
can drill in — `subscription_id=directory` is the tenant-scoped set, and
`resource_group` compares case-insensitively because ARM treats `Prod` and
`prod` as the same place.

`/attack-paths/choke-points` answers a different question from the list: not
which routes exist but which single change closes the most of them. `severs` is
verified by removing the link and re-asking the whole question, so it is what
actually closes; `on_routes` is the larger count of routes the link merely sits
on, carried beside it because the gap is the point — a link on twenty routes
that closes three is a link with a way round, and promising twenty would be a
number the customer can check and find wrong. `closes` names the routes, because
a count is a claim and those are its working.

Its own endpoint rather than a field on the list, because it costs a full
re-traversal per candidate and the list is read far more often than the question
is asked. Only removable links are candidates — a storage account has to live
somewhere, so containment is never offered.

`/findings/{id}/provenance` answers "how do you know?" — the readings the
finding rests on, each with the listing it came from, when the *provider* was
read, the actions the read was made under, and the hash of the payload. The
finding's own `evidence` block is an excerpt of what the rule saw; this is the
citation for it, and the difference is whether a customer has to accept the
claim or can check it.

`evidence: null` means no citation was recorded — a finding raised before
CloudGuard tracked this. `[]` would mean the rule reads nothing, and answering
the first as the second would make a claim about the rule out of a gap in our
own history; `meta.recorded` says which. `age_seconds` is computed here rather
than left to the client, because a carried reading is older than the scan that
raised the finding and a client would measure it against its own clock.
`payload_available` is asked of the blob store rather than inferred from the
hash: retention prunes payloads on their own schedule, and a citation whose
bytes have aged out is still a true statement about what was read. Where the
scan itself has been deleted the reading's `outcome`, `item_count` and
`permissions` come back `null`/`[]` — "we no longer hold that", never `0`,
which would claim the listing came back empty.

Its own endpoint rather than a field on the finding, like `/attack-paths`: the
page answering "what is wrong" must not wait on a question most readers never
ask.

Each citation also carries `endpoints` — `[{path, api_version}]`, what the
reading actually called. The api-version is the half that settles an argument: a
field absent from a stored capture is a setting nobody set, or a contract too
old to return it, and a rule reading the second as the first raises a finding
out of CloudGuard's own staleness. Empty where the scan has been pruned, or
where the reading predates this being recorded — never a claim the task called
nothing. `/scans/{id}/collection` carries the same field per reading.

`/findings/{id}/attack-paths` answers whether this finding's asset stands on a
route from an internet-facing asset to a sensitive one, and where on it —
`asset_role` is `ENTRY`, `STEP` or `TARGET`, which is what decides the action:
an entry point is how somebody gets in, a target is what they came for, and a
hop in between is usually the cheapest link to cut. Membership is asked of the
whole route rather than of its endpoints.

It is a separate request rather than a field on the finding because it costs a
graph build, and the page that answers "what is wrong" must not wait on one. A
finding with no asset — tenant-wide — returns an empty list rather than a 404:
"on no route" is a true answer. An empty list is never an all-clear, and the UI
says so: what counts as sensitive is declared per subscription, so an estate
that has classified nothing produces no routes at all.

`/reports/{kind}` renders `executive` or `technical` from the evidence that
exists right now — nothing is queued and nothing is stored. It is the one
endpoint that does **not** return the response envelope: the body is a PDF or an
HTML document, because wrapping a document in `{ "data": ... }` would make every
consumer unwrap and re-encode it. Errors on this path still use the envelope.

`format=html` returns the same document the PDF is printed from, so a report can
be read without downloading one — and a deployment whose native PDF libraries
are missing still produces something useful while that is fixed. A server that
cannot render PDFs answers 503 `NOT_CONFIGURED` rather than 500.

`days` (1–365, default 30) is the **activity window**: how far back verified
fixes, completed remediation work and the trend line reach. It does not filter
the posture, which is a reading of now — a security score is not a thing that
has a date range.

`sections` is a comma-separated subset of `top_risks`, `attack_paths`,
`compliance`, `remediation`, `findings` (`findings` only means anything in the
technical report). Omit the parameter for all of them; pass it empty for none,
which is a posture-only report. An unknown name is refused with 422 rather than
ignored — a misspelling that silently produced a document without the section
somebody asked for is the one failure a report cannot afford. Whatever is left
out is *named on the cover as excluded*, so a reader downstream can tell a
choice from an absence of evidence. The posture block and the evidence caveats
are not optional either way.

`/dashboard` carries two things the screens could not otherwise show without a
second request each. `coverage.categories` is the last scan's evidence grouped
by category with an `incomplete` count — PARTIAL counts with FAILED, because a
truncated listing cannot support "none of them are public" — so a reader is told
*which* part of the estate could not be read rather than only how much.
`top_risks[]` carries `kind` and the three context levels the score was built
from (`internet_exposure`, `data_sensitivity`, `asset_criticality`), which are
already columns on the row and cost no extra query; they let a rank be read as a
reason rather than as an assertion.

`remediation_activity` is eight weeks of findings raised, verified fixed and
reopened, grouped from the finding-event log rather than from the findings
themselves — `first_detected_at` and `resolved_at` are two points on a line, and
a finding raised, fixed, regressed and fixed again is indistinguishable from one
raised and fixed once. Reopenings are reported separately and never netted
against fixes.

Attack paths and changes stay on their own endpoints and are fetched separately
by the dashboard. A path costs a graph build and changes are a windowed feed, so
folding either into this payload would make the numbers everybody came for wait
on the two panels nobody scrolls to first.

`/risks` lists **live** risks unless a `status` is named: a finding risk while
its finding is open, a scenario until the route closes. A risk row outlives the
finding it was scored from, and listing every row ever raised made the page
disagree with the dashboard about the same estate on the same day. The rule is
settled rather than strict — a risk linked to no finding at all is still
listed, because the absence of a link is not evidence that a risk is over.

`GET /risks/{id}` returns `observed_at` on a scenario: when the route was last
seen, resolved from the scan that saw it. `null` where that scan has been pruned
or the route predates this being tracked — both mean "we cannot say when", and
the page renders that rather than a date it cannot support. A finding risk
carries none, taking its reading from the finding it was scored from.

`/compliance` reads the rule catalogue's `compliance_mappings` against the
framework catalogue in `app/compliance/catalog.py` and this organization's
latest scan. Each control resolves to FAILING, INCONCLUSIVE, PASSING,
NOT_ASSESSED or NOT_COVERED — and `coverage_ratio` counts conclusions
(pass **or** fail), never passes, because a share-of-passing figure would be a
compliance score and this API does not issue those.

---

## 2. Response Envelope

Consistent shape for every response:

```json
{ "data": {}, "error": null, "meta": {} }
```

Errors:

```json
{
  "data": null,
  "error": { "code": "CLOUD_ACCOUNT_NOT_FOUND", "message": "Cloud account not found" },
  "meta": {}
}
```

---

## 3. Authentication

```
React → Supabase Auth → JWT → FastAPI → Validate JWT → Get user ID
      → Get organization membership → Check role → Perform operation
```

The frontend may use the Supabase publishable key. **Never** expose the Supabase service-role/secret key in the browser. See `SECURITY.md`.
