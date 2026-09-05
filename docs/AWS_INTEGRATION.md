# CloudGuard — AWS Integration

The AWS analogue of [`AZURE_INTEGRATION.md`](AZURE_INTEGRATION.md). Read §1
first: it is the difference between this being an integration and a plausible
description of one.

---

## 1. Verification checklist — **not yet run**

> **Nothing in `app/connectors/aws/` has been executed against a live AWS
> account.** Every IAM action name, response key, pagination shape and the
> CloudFormation template is written from AWS's published reference. Until the
> checklist below has been completed against a real account, AWS is reachable
> through the API and **is not offered in the UI**.

`MULTI_CLOUD.md` §8 step 2 said this work was "not startable from a desk", and
it was started from one. That was a deliberate trade, and the checklist is what
bounds it.

IAM makes the risk worse than the Azure equivalent, which is why the gate
exists. ARM validates a role definition atomically: one action string that is
not a real provider operation fails the entire deployment and the customer sees
"Deployment Failed". **IAM accepts a policy naming an action that does not
exist** and simply grants nothing — the stack creates, the console is green, and
the read fails several minutes into a scan with `AccessDenied`.

| # | Check | Why it cannot be assumed |
|---|---|---|
| 1 | The stack creates without error in a real account | An unknown action grants nothing and is not reported |
| 2 | Every action in `INLINE_READ_ACTIONS` appears in the created role's policy exactly as written | IAM normalises nothing and warns about nothing |
| 3 | `sts:AssumeRole` succeeds **with** the external id | The whole grant rests on it |
| 4 | `sts:AssumeRole` **fails** without the external id | If it succeeds, the trust policy's condition is not doing its job |
| 5 | `ec2:DescribeRegions` returns the enabled set, and a disabled region is never attempted | The fan-out's size is decided from this |
| 6 | One full scan returns COMPLETE or a *named* denial for every task | A silent gap reads as a clean estate |
| 7 | `iam:GetCredentialReport` returns content after `GenerateCredentialReport`, within the retry window | The report is generated asynchronously; the window is a guess |
| 8 | Each per-bucket call is made in the bucket's own region | Otherwise `PermanentRedirect`, which reads as a permission problem |
| 9 | `organizations:ListAccounts` returns member accounts from the management account | Discovery produces nothing otherwise, and a connection scans one account while claiming an organization |
| 10 | The response shapes match what `normalizer.py` reads | A wrong key silently normalises to an empty estate |
| 11 | An SNS subscription confirms, and a notification reaches the webhook | The confirmation is fetched, not echoed — a different mechanism from Azure's |
| 12 | `iam:GetPolicyVersion` returns a document, and the URL-decode produces JSON | AWS returns it percent-escaped; a wrong decode reads as a policy granting nothing |
| 13 | `iam:ListInstanceProfiles` returns the role behind each profile | Without it the graph's first capability hop draws nothing |
| 14 | A region with GuardDuty, Security Hub or Access Analyzer switched off answers with an error rather than an empty list | The client treats those codes as an answer; a different code would read as a failed read |
| 15 | `config:DescribeConfigurationRecorderStatus` names recorders the way `DescribeConfigurationRecorders` does | They are joined on `name`, and a mismatch reads as "not recording" |
| 16 | A trail's `CloudWatchLogsLogGroupArn` has the shape `arn:aws:logs:<region>:<account>:log-group:<name>:*` | The log group name is parsed out of it; a different shape reads as "no filter on the trail's log group" |
| 17 | `logs:DescribeMetricFilters` returns `metricTransformations` with `metricNamespace` and `metricName` as spelled | The alarm is matched to the filter on exactly that pair |
| 18 | `iam:ListEntitiesForPolicy` accepts `arn:aws:iam::aws:policy/AWSSupportAccess` and answers with `PolicyRoles` / `PolicyUsers` / `PolicyGroups` | All three lists are read; a fourth shape or a different ARN reads as "nobody holds it" |

Once all eighteen pass: remove the `# UNVERIFIED` markers in
`app/connectors/aws/iam.py`, drop the warnings from the module docstrings in
`app/connectors/aws/`, and enable AWS in the provider picker.

---

## 2. Auth model: one cross-account role, assumed with an external id

Azure has two grants that fail independently — Entra admin consent for Graph,
and an ARM role. AWS has one. That single structural difference produces every
other difference in this document.

```
CloudGuard's own principal            Customer's account
  (AWS_PRINCIPAL_ARN)                   CloudGuardScannerRole
        |                                       |
        |  sts:AssumeRole + ExternalId          |
        +-------------------------------------->|
                                                |
                             SecurityAudit + ViewOnlyAccess
                             + one small inline read policy
```

**CloudGuard stores no customer credential.** The role ARN is a name; the
external id is a name the customer's own trust policy requires. Neither grants
anything on its own — the same property `cloud_account.py` has claimed since
v0.1, kept rather than given up.

### 2.1 CloudGuard's own principal

One IAM user (or role) in CloudGuard's account, whose only permission is
`sts:AssumeRole`. Set on the API:

```
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_PRINCIPAL_ARN=arn:aws:iam::<cloudguard-account-id>:user/cloudguard-scanner
```

`AWS_PRINCIPAL_ARN` is what the generated template names, so it must match
character for character: a wrong value fails when the customer clicks deploy,
not when CloudGuard calls.

The blast radius of losing the key is bounded twice over — it can assume only
roles that already name it, and every one of those additionally requires an
external id CloudGuard generated and never published.

### 2.2 The external id

Generated server-side, per connection, at the moment the connection is created,
and **never accepted from a request body**.

Without it, anybody who learns CloudGuard's account id can create a role
trusting CloudGuard and have it scan an environment on their behalf. This is the
confused deputy, and it is the standard way third-party CSPM integrations get
this wrong. `test_aws_iam.py` asserts the trust policy carries the
`sts:ExternalId` condition, and that assertion is not negotiable.

`RoleAssumer` refuses to assume a role without one, because an assume-role call
with no external id *succeeds* against a role whose trust policy does not
require one — which is exactly the misconfiguration CloudGuard must not
participate in.

---

## 3. Onboarding flow

Three steps rather than Azure's four, because there is no consent screen.

1. **Name the scope.** An organization, an organizational unit, or a single
   account — and in every case an account id, because there is nothing to
   assume a role *in* until one is named. Azure's tenant root needs no id
   because consent reports the tenant; AWS has no equivalent.
2. **Deploy the stack.** A Launch Stack link opens CloudFormation with the
   template loaded and the external id filled in. StackSets cover the
   organization-wide case that a management group covers on Azure.
3. **Choose the accounts.** CloudGuard lists what it can see beneath the scope
   and the customer decides which are in scope.

CloudGuard polls in the background. **One successful `sts:AssumeRole` sets both
`consent_status` and `rbac_verified_at`** — AWS has one grant, and leaving the
first permanently PENDING would make `is_verified` false for a connection that
verifies (`DECISIONS.md` §70).

The organization id arrives from `organizations:DescribeOrganization` on that
same probe, never from the customer. An account outside an organization answers
with an error, which is not a failure: a standalone account is a boundary of one
and names itself.

### The artifact

Generated from the declared permission set, never hand-maintained — the pattern
`azure/rbac.py` established and the most valuable thing the Azure connector
built (`MULTI_CLOUD.md` §1). Served from the same token-gated, CORS-open
endpoint the ARM template uses, for the same reason: the provider's console
fetches it and carries no CloudGuard session.

Most of the grant comes from AWS's own `SecurityAudit` and `ViewOnlyAccess`
managed policies. They are maintained by AWS, so a service that gains a read
action is covered without a redeploy, and — more to the point — no string in
them can be a typo of ours. The inline policy holds only what they do not, which
keeps the hand-written surface small enough to review by eye.

### Per-account roles

An organization-wide connection assumes one role in each member account. The
same stack is deployed into each, so the ARNs differ only by account id and
discovery writes them without asking. The external id is shared across them, and
correctly: it identifies the *relationship*, not the account.

### Revocation

`aws cloudformation delete-stack`, run by the customer. CloudGuard cannot delete
a role in someone else's account and would not want the permission —
`iam:DeleteRole` there is far more dangerous than the read access it would
withdraw. Revocation is then *verified by the access failing*, using the same
read-only probe that verified it working.

---

## 4. Collection: the region dimension

The one structural difference that reaches above the connector seam.

Azure's ARM lists a subscription's resources globally. AWS reads almost
everything per region, so an account with seventeen enabled regions produces
seventeen readings of `security_groups`. Readings are scoped by key **and**
region; verdicts stay per evidence key, and a key is trustworthy only if every
region's reading of it was (`DECISIONS.md` §69).

`ec2:DescribeRegions` is read before the plan exists, because the plan's shape
depends on the answer. When that read fails, the plan still emits one task per
regional key so the executor can record them SKIPPED — a key with **no reading
at all** raises no gap, so a rule would evaluate against an empty payload and
report PASS over an estate nobody looked at.

Global services — IAM, S3's bucket list, Organizations, STS — are read once.
Asking them per region returns the same answer seventeen times.

Resource Explorer is **not** used. `MULTI_CLOUD.md` §4 prefers it, and the
preference still holds, but it is opt-in and a customer without it must be
scannable rather than reported as empty. Enumeration is what every customer
needs; an aggregator is an optimization on top of a working one.

---

## 5. What the role can and cannot read

Every action is a read of configuration. There is no `s3:GetObject`, no
`kms:Decrypt`, no `secretsmanager:GetSecretValue` and no `ssm:GetParameter` —
CloudGuard can tell a customer their bucket is public without being able to read
one byte out of it, and that claim is checkable from one tuple in
`app/connectors/aws/iam.py`.

One action reads like a write and is not.
`iam:GenerateCredentialReport` creates nothing and changes no configuration; it
asks IAM to compile a report about state that already exists. Without it, every
credential-age check reports UNKNOWN.

---

## 6. Change-triggered scanning

A schedule promises the environment is re-read at least this often; this
promises a change is *noticed*. The delivery path is **EventBridge → SNS →
HTTPS**, because EventBridge cannot post to an arbitrary endpoint on its own and
an API destination would put a credential of ours in the customer's account.

Three commands where Azure needs one, all generated per connection and carrying
a token that works for that connection alone. CloudGuard creates none of it: the
topic and the rule are writes in the customer's account, and holding no write
permission is the strongest claim this product makes.

**The confirmation is fetched, not echoed**, and that is the one place the two
clouds differ in a way that matters. SNS hands over a `SubscribeURL`; fetching
it is an outbound request triggered by an inbound payload, from an endpoint
anyone with the connection's token can reach. Only `sns.<region>.amazonaws.com`
(and `.com.cn`) is accepted — everything else is refused rather than fetched
(`DECISIONS.md` §76).

---

## 7. Error handling

The same three outcomes the Azure connector uses, because the rule engine
already speaks them.

* **A denial costs one evidence key**, not the connection. `AccessDenied` on the
  KMS listing degrades the checks that read keys and nothing else.
* **A service that is switched off is an answer, not a gap.** A region with no
  GuardDuty detector has an answer — there is no detector — and reporting it as
  a failed read would degrade a rule that has all the evidence it needs. The
  same goes for a bucket with no encryption configuration, which AWS reports as
  an error code and which *is* the finding.
* **A truncated listing is PARTIAL, never a shorter list.** A list missing an
  unknown number of entries cannot support "none of them are public".
