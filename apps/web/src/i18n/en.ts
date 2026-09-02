/**
 * English strings.
 *
 * Every user-facing string goes through here even though English is the only
 * language in the MVP. Adding Albanian later is then a new dictionary rather
 * than a hunt through JSX for hardcoded text -- which is the cheap-now,
 * expensive-later trade the spec calls out.
 */
export const en = {
  app: {
    name: "CloudGuard",
    tagline: "Cloud security posture, in plain language",
  },
  nav: {
    dashboard: "Dashboard",
    changes: "Changes",
    reports: "Reports",
    settings: "Settings",
    assets: "Assets",
    findings: "Findings",
    risks: "Risks",
    attackPaths: "Attack paths",
    remediation: "Remediation",
    scans: "Scans",
    rules: "Rules",
    connections: "Connections",
    compliance: "Compliance",
    signOut: "Sign out",
  },
  account: {
    menu: "Account menu",
    signedInAs: "Signed in as",
    organization: "Organization",
    switchTo: "Switch to",
    currentOrg: "Current organization",
    newOrganization: "Create organization",
    settings: "Cloud connections",
    unknownUser: "Signed in",
    removeOrg: "Remove organization",
    removingOrg: "Removing\u2026",
    removeOrgTitle: "Remove",
    removeOrgDetail:
      "Its cloud connections, discovered subscriptions, assets, scan history, findings and risks are all deleted with it. This cannot be undone.",
    removeOrgOwnerOnly: "Only an owner can remove an organization.",
    keep: "Keep it",
  },
  auth: {
    signIn: "Sign in",
    signUp: "Create your account",
    email: "Email address",
    password: "Password",
    continue: "Continue",
    sendLink: "Send sign-in link",
    checkEmail: "Check your email",
    linkSentTo: "We sent a sign-in link to",
    confirmSentTo: "We sent a confirmation link to",
    resetSentTo: "We sent a password reset link to",
    openOnThisDevice: "Open it on this device to continue.",
    passwordNotice:
      "Your password goes straight to Supabase and never to CloudGuard's servers — this app only ever verifies the token Supabase issues.",
    continueWithMicrosoft: "Continue with Microsoft",
    orDivider: "or",
    forgotPassword: "Forgot password?",
    magicLinkInstead: "Email me a sign-in link instead",
    passwordInstead: "Use a password instead",
    noAccount: "Don't have an account?",
    haveAccount: "Already have an account?",
    createOne: "Create one",
    resetTitle: "Reset your password",
    resetIntro: "Enter your email and we'll send you a link to set a new one.",
    sendReset: "Send reset link",
    newPassword: "New password",
    setPassword: "Set new password",
    passwordUpdated: "Password updated",
    passwordTooShort: "Use at least 8 characters.",
    showPassword: "Show password",
    hidePassword: "Hide password",
    creatingAccount: "Creating account\u2026",
    signingIn: "Signing in\u2026",
    sending: "Sending\u2026",
    backToSignIn: "Back to sign in",
    useAnotherAddress: "Use a different address",
    microsoftHint:
      "Signing in with Microsoft does not give CloudGuard access to your Azure resources \u2014 that is a separate consent step.",
  },
  onboarding: {
    createOrg: "Create your organization",
    orgName: "Organization name",
    industry: "Industry",
    country: "Country",
    create: "Create organization",
    step: "Step",
  },
  connect: {
    title: "Connect your Azure environment",
    readOnlyPromise: "CloudGuard requests read-only access. It never modifies your Azure resources.",
    whatWeAccess: "What CloudGuard can see",
    whatWeCannot: "What CloudGuard cannot do",
    noSecrets:
      "You never give CloudGuard a password, client secret, or certificate. CloudGuard authenticates as its own application against your directory, so there is no credential of yours for us to store or lose.",
    step1: "Grant admin consent",
    step1Detail:
      "Your Entra ID Global Administrator approves read access to directory data. One click, applied tenant-wide.",
    step2: "Deploy the scanner role",
    step2Detail:
      "Click Deploy to Azure to grant CloudGuard read-only access at the scope you chose. Nothing to type — the template is pre-filled.",
    accountName: "Connection name",
    openConsent: "Open admin consent",
    verified: "Connection verified",
  },
  connection: {
    title: "Cloud connections",
    intro:
      "One connection per tenant or management group. Subscriptions beneath it are discovered, not registered by hand \u2014 so an environment created next month gets scanned instead of quietly missed.",
    connectAzure: "Connect Azure",
    noConnections: "No cloud environment connected yet.",
    noConnectionsHelp:
      "Connecting takes two grants and about three minutes. You will not be asked for a tenant id, a subscription id, or any credential.",
    step: "Step",
    of: "of",
    stepConsent: "Grant admin consent",
    stepDeploy: "Deploy the scanner role",
    scope: "Scope",
    connectionName: "Connection name",
    managementGroupId: "Management group id",
    subscriptionId: "Subscription id",
    create: "Continue",
    cancelSetupAction: "Cancel setup",
    resumeSetup: "Resume setup",
    setupCancelled: "Setup cancelled",
    readyToScan: "Ready to scan",

    // Scheduling. Off by default, and the copy says why rather than leaving a
    // dropdown to explain itself: a customer choosing an interval is choosing
    // a recurring cost on their own Azure bill.
    scheduleTitle: "Automatic scanning",
    scheduleHelp:
      "A security report ages the moment it is written \u2014 cloud environments change daily, and a scan from last month describes an environment that has moved on. Choose how often CloudGuard should re-read this one.",
    scheduleLabel: "Re-read this environment",
    scheduleManual: "Only when I ask",
    scheduleEvery6Hours: "Every 6 hours",
    scheduleDaily: "Every day",
    scheduleEvery3Days: "Every 3 days",
    scheduleWeekly: "Every week",
    scheduleSaving: "Saving\u2026",
    scheduleSaved: "Saved",
    scheduleOn: "Scanning automatically",
    scheduleOff: "Manual scanning only",
    scheduleFirstRunNote:
      "The first automatic scan starts within a few minutes; after that it runs on the interval you chose.",
    scheduleNotReady:
      "This connection cannot scan yet, so there is nothing to schedule. Finish the two grants above first.",
    scheduleFloorNote:
      "An interval rather than a time of day: CloudGuard promises to read this environment at least this often, not to start at a particular minute.",

    // Change-triggered scanning. Two things have to survive the copy: that
    // turning it on wires nothing up on its own, and *why* -- CloudGuard holds
    // no write permission in the customer's tenant and will not ask for one.
    changeTitle: "React to changes",
    changeHelp:
      "A schedule reads this environment on a clock. This reads it when something actually moves \u2014 a port opened, a role assigned, a storage account made public \u2014 so the finding arrives while whoever made the change is still at their desk.",
    changeOn: "Listening for changes",
    changeOff: "Not listening",
    changeEnable: "Turn on change detection",
    changeDisable: "Turn off",
    changeSaving: "Saving\u2026",
    changeNotWired:
      "The webhook is open. Nothing reaches it until you run the command below in each subscription \u2014 CloudGuard cannot create that subscription for you, because it holds no write permission in your tenant and does not ask for one.",
    changeCommandsLabel: "Run this once per subscription",
    changeCopyCommand: "Copy command",
    changeNoEndpoint: "CloudGuard has no public address to receive deliveries",
    changeNoEndpointHelp:
      "This deployment has no public API base URL configured, so there is no endpoint for Event Grid to deliver to. Change detection cannot be wired up until that is set.",
    changeLastEvent: "Last change heard",
    changeNeverHeard: "Nothing yet",
    changePending: "A change is settling; a scan starts once the environment is quiet",
    changeTiming:
      "A burst of changes becomes one scan, not one per event: CloudGuard waits for {quiet} minutes of quiet, and scans a connection at most once every {interval} minutes for change.",

    // The empty state, which is the first meaningful screen in the product.
    readWhatItDoes: "Read what CloudGuard will do",
    hideWhatItDoes: "Hide the detail",
    readOnlyPromise:
      "The role CloudGuard asks for is read-only. It cannot change your configuration, and it cannot read the data inside your storage accounts, databases or key vaults.",
    permissionsTitle: "The exact access CloudGuard asks for",
    graphPermissions: "Directory permissions",
    rbacRole: "Azure role",
    writesPerformed: "Writes performed",
    permissionsUnavailable:
      "This list comes from the API and could not be loaded. It is the same list Microsoft shows on the consent screen, which is the copy that actually governs.",

    // The connections list: one row per connection, opened for the detail.
    columnConnection: "Connection",
    columnStatus: "Status",
    columnSubscriptions: "Subscriptions",
    columnLastRead: "Last read",
    columnActions: "Actions",
    subscriptionsHeading: "Subscriptions",
    allInScope: "all in scope",
    someInScope: "in scope",
    expandRow: "Show this connection's detail",
    collapseRow: "Hide this connection's detail",
    scanNow: "Scan now",
    scanStarting: "Starting\u2026",
    scanQueued: "Scan queued",
    changeSchedule: "Change schedule",
    cadenceTitle: "How often this is read",
    cadenceLastRead: "Last read",
    cadenceNeverRead: "Not yet",
    cadenceClock: "On a clock",
    cadenceOnChange: "On change",
    accessTitle: "Access",
    readerRole: "Reader role",
    verifiedOn: "verified",
    writePermission: "Write permission",
    noneByDesign: "None, by design",
    recheckAccess: "Re-check access",
    firstSeen: "first seen",
    newSinceLastRead: "new since last read",
    excludedByYou: "excluded by you",
    moreSubscriptions: "more subscriptions",
    discoveryPromise:
      "A subscription created in this tenant appears here on the next read.",
    scopeFootnote:
      "Unticking a subscription stops CloudGuard reading it. Existing findings for it are kept and marked out of scope, not deleted.",

    noSubscriptionsTitle: "No subscriptions found yet",
    noSubscriptionsBody:
      "Both grants are working, but CloudGuard cannot see any subscription to scan. A role assigned moments ago can take a few minutes to show up, and a role deployed to the wrong scope will never show up at all.",
    lookAgain: "Look for subscriptions again",
    lookingAgain: "Looking…",
    runFirstScan: "Run a scan",
    noSubscriptionsYet: "No subscriptions discovered yet",
    noSubscriptionsYetHelp:
      "The connection is verified but nothing was found beneath it. If the scanner role was deployed at a narrower scope than this connection covers, no subscription is visible to it.",
    cannotStartConsent: "CloudGuard cannot start the consent flow",
    cannotDeployYet: "CloudGuard cannot generate the deployment yet",
    whoYouNeed: "Who you will need",
    whoYouNeedDetail:
      "Admin consent needs a work or school account that is a Global Administrator. A personal Microsoft account \u2014 outlook.com, hotmail.com, live.com \u2014 cannot grant it, even if that account owns the subscription. Granting read access then needs Owner or User Access Administrator on the scope you chose. These are different permissions, and often different people.",
    noGuidsNeeded:
      "You will not be asked for your tenant id. Entra reports it when your administrator consents, which is also what binds this connection to your directory.",
    openConsent: "Open admin consent",
    copyConsentLink: "Copy link for your administrator",
    consentExpiry: "This link works once and expires in 30 minutes.",
    waitingForConsent: "Waiting for admin consent\u2026",
    consentGranted: "Admin consent granted",
    copied: "Copied",
    waitingForAccess: "Waiting for the read access grant\u2026",
    verified: "Connection verified",
    discovered: "subscriptions found",
    inScopeCount: "subscriptions in scope",
    inScope: "Scan this subscription",
    saveScope: "Save selection",
    done: "Done",
    lastDiscovery: "Last checked",
    neverDiscovered: "Not yet discovered",
    consentSignal: "Admin consent",
    accessSignal: "Read access",
    readySignal: "Ready to scan",
    granted: "Granted",
    notGranted: "Not granted",
    notVerified: "Not verified",
    yes: "Yes",
    notYet: "Not yet",
    whatItReads: "The exact operations CloudGuard performs",
    noWriteActions:
      "No write actions and no data-plane access. CloudGuard cannot modify anything, and cannot read the contents of your storage or databases.",
    principalId: "Service principal",
    scopePath: "Scope",
    cancel: "Cancel",
    cancelSetup: "Cancel setup",
    close: "Close",
    finishLater: "Finish later",
    discard: "Discard connection",
    discarding: "Discarding\u2026",
    discardTitle: "Discard this half-finished connection?",
    discardDetail:
      "Nothing has been scanned yet, so there is nothing to lose. You can also leave it and pick up where you left off.",
    remove: "Remove connection",
    removing: "Removing\u2026",
    removeTitle: "Remove this connection?",
    removeDetail:
      "Its discovered subscriptions, their assets, scan history and findings are deleted with it. This cannot be undone.",
    revokeTitle: "Revoke access in Azure",
    revokeIntro:
      "Removing the connection here deletes CloudGuard's copy of the data. It does not take away the access you granted \u2014 run these in Azure to do that.",
    checkRevoked: "Check whether access is gone",
    checking: "Checking\u2026",
    stillHasAccess: "CloudGuard can still read this environment",
    accessGone: "Confirmed: access revoked",
    removeAzureNote:
      "This does not revoke anything in Azure. To withdraw the access you granted, remove CloudGuard from Enterprise applications in Entra ID and delete its role assignment.",
    keep: "Keep it",
    notConfigured: "This CloudGuard deployment cannot connect Azure yet",
    notConfiguredDetail:
      "This is a setup step on CloudGuard's side, not yours \u2014 whoever operates this deployment needs to register its Entra application (docs/AZURE_INTEGRATION.md \u00a72.1).",
  },

  // The setup wizard. Its own block rather than more keys on `connection`,
  // because these strings are read in one sitting by somebody who has never
  // seen the product before, and they have to make sense in sequence.
  setup: {
    title: "Connect Azure",
    intro:
      "Two grants and about three minutes. You will not be asked for a tenant id, a subscription id, or any credential.",
    backToConnections: "Cloud connections",
    railTitle: "What the three minutes look like",

    stepScope: "Choose the scope, and name it",
    stepScopeDetail:
      "A whole tenant, one management group, or a single subscription. The name is yours \u2014 it is what you will see on every finding.",
    stepConsent: "A Global Administrator grants admin consent",
    stepConsentDetail:
      "One Microsoft prompt, once per tenant. If that is not you, CloudGuard gives you a link to send.",
    stepDeploy: "Deploy the reader role",
    stepDeployDetail:
      "One ARM template in Azure Portal. Needs Owner at the scope you chose \u2014 the form says which, before you start.",
    stepSubscriptions: "Then CloudGuard finds the rest",
    stepSubscriptionsDetail:
      "Every subscription beneath the scope is discovered and kept in step \u2014 including the ones created after today.",

    // Consent step.
    consentTitle: "Ask a Global Administrator to consent",
    consentBody:
      "This is one Microsoft prompt, granted once for the whole directory. Nothing is scanned by it \u2014 it is what lets CloudGuard ask Azure who exists.",
    notAdmin: "I am not a Global Administrator",
    handoffTitle: "Send it to someone who is",
    handoffBody:
      "The link works once and expires in 30 minutes, so send it when they are at their desk. This page keeps waiting; you can close it and come back.",
    handoffMessage:
      "Please open this link and approve read-only access for CloudGuard, our cloud security tool. It needs a Global Administrator, takes one click, and grants no permission to change anything:",
    copyMessage: "Copy the message",
    consentFailed: "Admin consent did not complete",
    consentRetry: "Start consent again",

    // Deploy step.
    deployTitle: "Grant read access at the scope you chose",
    deployBody:
      "The template is pre-filled. Azure Portal opens on a review screen; there is nothing to type.",
    deployToAzure: "Deploy to Azure",
    stalledTitle: "This is taking longer than a deployment should",
    stalledBody:
      "The three things that usually explain it, in the order they are worth checking:",
    stalledPropagation:
      "A role assigned in the last few minutes has not propagated yet. Waiting a little longer is the fix.",
    stalledScopeTenant:
      "The deployment landed on a subscription rather than the tenant root. A connection covering the whole tenant only sees a role assigned at the root management group.",
    stalledScopeGroup:
      "The deployment landed on a subscription rather than on the management group this connection covers.",
    stalledScopeSubscription:
      "The deployment landed on a different subscription from the one this connection covers.",
    stalledOwner:
      "Whoever ran it holds Contributor rather than Owner or User Access Administrator. Contributor can deploy a template but cannot assign a role, and Azure reports that as a failed deployment rather than a missing permission.",
    checkAgain: "Check again",
    checking: "Checking\u2026",
    changeScope: "Choose a different scope",

    // Subscriptions step.
    discoverTitle: "Looking for subscriptions",
    reviewTitle: "Choose what CloudGuard reads",
    reviewBody:
      "Everything beneath the scope is in scope by default. Unticking one stops CloudGuard reading it; existing findings are kept and marked out of scope, not deleted.",
    nothingInScopeTitle: "Nothing is ticked, so nothing will be read",
    nothingInScopeBody:
      "Every subscription found beneath this scope is out of scope. Tick at least one above, or leave it — the connection stays and picks up whatever is ticked later.",
    doneTitle: "Connected",
    doneBody:
      "Nothing is read until a scan runs. The first one is worth starting now \u2014 after that, the scans page decides how often this environment is re-read.",
    backToList: "Back to connections",

    // Footer, on every step, and the way back in from the connections list.
    continueSetup: "Continue setup",
    finishLater: "Finish later",
    paused: "Setup is paused",
    pausedBody:
      "Nothing has been scanned and nothing was granted. Pick it up whenever the right person is available.",
  },

  dashboard: {
    title: "Security posture",
    score: "Security score",
    outOf: "out of 100",
    trendTitle: "Score over time",
    trendTooShort:
      "One scan so far. A second one gives CloudGuard something to compare against, and this becomes a line.",
    scoreWorse: "since last scan",
    noPreviousScan: "No previous scan to compare against",
    sinceLastScan: "since last scan",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    topRisk: "Top risk",
    topRisks: "What matters most right now",
    remediation: "Verified fixes",
    resolvedRecently: "verified fixed in the last 30 days",
    coverage: "Assessment coverage",
    coverageHelp:
      "How much of your environment CloudGuard could conclusively assess. Tracked separately from your score so the score stays easy to explain.",
    assets: "Assets discovered",
    noScans: "No scan has run yet",
    noScansHelp: "Connect an Azure subscription and run your first scan to see your posture.",
    runFirstScan: "Run your first scan",
    allClear: "No open findings. Nice.",
    couldNotLoad: "Couldn't load your dashboard",
    signInAgain: "Sign in again",
    openFindings: "Open findings",
    lastScan: "Last scan",
  },
  findings: {
    title: "Findings",
    empty: "No findings match these filters.",
    whyItMatters: "Why this matters",
    evidence: "Evidence",
    howToFix: "How to fix it",
    riskScore: "Risk score",
    effort: "Estimated effort",
    minutes: "min",
    asset: "Asset",
    firstSeen: "First detected",
    lastSeen: "Last detected",
    resolvedBy: "Verified fixed by scan",
    actions: "Actions",
    assign: "Assign",
    markInProgress: "Mark in progress",
    acceptRisk: "Accept risk",
    rescan: "Rescan to verify",
    rescanQueued: "Rescan queued. CloudGuard will close this finding automatically if the fix worked.",
    acceptReason: "Why are you accepting this risk?",
    confirm: "Confirm",
    cancel: "Cancel",
    cannotResolveManually:
      "Findings are closed by a scan that confirms the fix, never by hand.",
    scoreBreakdown: "How this score was calculated",
    compliance: "Related controls",
  },
  assets: { title: "Assets", empty: "No assets discovered yet.", openFindings: "Open findings" },
  risks: {
    title: "Risks",
    empty: "No risks recorded yet.",
    // A scenario is not a louder finding. It is several of them seen as one
    // thing, and the label has to carry that or it reads as duplication.
    scenarioBadge: "Attack path",
    escalationBadge: "Privilege escalation",
    scenarioIntro: "Several findings, seen as one route",
    escalationIntro: "A route to an identity that can grant itself more",
    routeLabel: "The route",
    cutLabel: "Severing it",
    // The scoring, said in the terms the breakdown actually stores. A customer
    // asking "why is this above the finding inside it" gets an answer rather
    // than a number.
    worstMember: "Worst finding on the route",
    amplifier: "Added for the route itself",
    cappedNote: "Capped at 100.",
    memberCount: "findings on this route",
    // The detail page. What the list can rank but cannot show: which findings
    // a risk was actually built from.
    backToRisks: "Risks",
    builtFrom: "What this risk is built from",
    builtFromScenario:
      "The findings on this route. Fixing any one of them breaks the route \u2014 the cheapest is usually the identity or the role, never the containment.",
    builtFromFinding:
      "The observation this risk scores. A finding is what CloudGuard saw; the risk is what it means for this asset, with this data, at this level of exposure.",
    noMembers: "No findings are linked to this risk.",
    noMembersDetail:
      "The findings it was built from have been deleted, most likely with the scan that raised them. The score is kept as history rather than recomputed from nothing.",
    theArithmetic: "How this score was reached",
    notFound: "That risk no longer exists",
    notFoundDetail:
      "It may have been deleted with the scan that raised it. The risks list shows everything CloudGuard currently ranks.",
  },
  attackPaths: {
    title: "Attack paths",
    intro:
      "The findings list says what is wrong. This says what is wrong \u2014 together. A jump box, an over-privileged identity and a storage account are three findings; the route between them is one problem, and it has one cheapest fix.",
    // The empty state has to distinguish three different nothings, because
    // they call for three different actions.
    emptyNoPaths: "Nothing exposed can reach anything sensitive",
    emptyNoPathsDetail:
      "CloudGuard found assets reachable from the internet and assets holding sensitive data, and no route between them.",
    emptyNoEntry: "Nothing is reachable from the internet",
    emptyNoEntryDetail:
      "A route has to start somewhere. No asset in this environment is exposed enough to be an entry point, so there is nothing for a path to begin from.",
    emptyNoTargets: "Nothing has been classified as sensitive",
    emptyNoTargetsDetail:
      "A route has to end somewhere worth reaching. Tag your storage and databases with a data classification, or set asset criticality, so CloudGuard knows what would actually cost you.",
    emptyNoScan: "No scan has run yet",
    emptyNoScanDetail:
      "Attack paths are built from what a scan found. Run one, and any route from an exposed asset to a sensitive one appears here.",
    hops: "hops",
    oneHop: "hop",
    from: "From",
    to: "To",
    route: "The route",
    cutHere: "Cut it here",
    cutHereDetail:
      "Removing this one link severs the route. Containment cannot be removed \u2014 a storage account has to live somewhere \u2014 so the fix is always an identity or a role.",
    entryPoints: "exposed assets",
    sensitiveTargets: "sensitive assets",
    exposure: "Exposure",
    sensitivity: "Sensitivity",
  },
  scans: {
    title: "Scans",
    runScan: "Run scan",
    empty: "No scans yet.",
    resources: "Resources",
    rules: "Rules run",
    findings: "Findings",
    cancel: "Cancel scan",
    details: "Details",
    hideDetails: "Hide details",
    duration: "Duration",
    startedAt: "Started",
    evaluated: "Resources evaluated",
    scope: "Scope",
    identity: "Identity used",
    initiator: "Started by",
    scheduled: "Scheduled",
    // A manual scan whose user record is gone. Distinct from
    // "Scheduled": somebody did ask for this one, and we no longer
    // know who.
    manualUnknownUser: "Started by hand",
    breakdown: "Open findings from this scan",
    deleteScan: "Delete",
    deleting: "Deleting\u2026",
    deleteTitle: "Delete this scan record?",
    deleteRecordOnly: "Delete record only",
    deleteRecordOnlyDetail:
      "Removes the execution log. Findings it raised stay \u2014 they describe your environment, not this run.",
    deleteWithFindings: "Delete record and its unresolved findings",
    deleteWithFindingsDetail:
      "Also deletes the unresolved findings this scan last detected. Verified fixes are never deleted \u2014 each one is the evidence a remediation worked.",
    cancelling: "Cancelling\u2026",
    // Replay. Every scan stores the provider's own JSON before interpreting
    // it, so a rule written after that scan ran can still be applied to it --
    // and doing so costs nothing in the customer's cloud.
    replay: "Re-evaluate",
    replayQueueing: "Queueing\u2026",
    replayHelp:
      "Runs today's rules against what this scan already collected. No Azure call, no consent, no cost to your throttle budget \u2014 CloudGuard kept the provider's own JSON, so a check written since can still be applied to it.",
    replayBadge: "Re-evaluated a stored capture",
    replayOfLabel: "Re-evaluation of an earlier scan",
    // The distinction that keeps a replay honest. Only a replay of the newest
    // capture may touch findings; an older one reports and stops.
    replayAdvisoryTitle: "What the rules would have found",
    replayAdvisoryDetail:
      "This capture is no longer CloudGuard's current picture of the environment \u2014 it has been read again since. The counts below say what today's rules would have made of it. No finding was created, resolved or reopened: a capture from before nobody looked at cannot verify a fix.",
    replayCurrentTitle: "Applied to your current picture",
    replayCurrentDetail:
      "This was still the newest capture for its subscriptions, so the results count: findings were raised, resolved and reopened exactly as a fresh scan would have done, without reading your cloud again.",
    wouldHaveFound: "Findings (would have)",
    stuckTitle: "Nothing has picked this scan up",
    stuckDetail:
      "A scan is collected by CloudGuard's worker within seconds of being queued. Minutes of silence means no worker is running \u2014 check that the Celery worker service is deployed and can reach Redis.",
    nothingFound: "No resources were found in this subscription",
    nothingFoundHelp:
      "Every resource category CloudGuard reads returned successfully and was empty, so there is nothing here to assess. If that is unexpected, check in Details which subscription this scan covered \u2014 a connection discovers every subscription it can see, including empty ones.",
    nothingFoundPartial:
      "Nothing was assessed, and some categories could not be read at all \u2014 see the gaps below. A category that failed is not the same as a category that was empty.",
    collectionTitle: "What was read",
    collectionSummary: "read completely",
    collectionPartial: "partial",
    collectionFailed: "failed",
    collectionSkipped: "skipped",
    collectionAllComplete: "Every listing was read in full.",
    collectionAffects: "Affected checks",
    outcomeComplete: "Read in full",
    outcomePartial: "Incomplete",
    outcomeFailed: "Could not read",
    outcomeSkipped: "Not attempted",
    partialHint:
      "An incomplete listing cannot support a pass, so the checks that needed it report unknown rather than clean.",
    partial: "Some data could not be collected — affected checks are marked unknown, not passed.",
  },
  rules: {
    title: "Rule library",
    empty: "No rules loaded.",
    // A withdrawn rule is not a check CloudGuard runs, and listing it beside
    // the ones it does run made the catalogue overstate what is being checked.
    // The row exists because findings it raised still name it.
    withdrawn: "Withdrawn",
    withdrawnHelp:
      "This check has been taken out of the rule registry, so it no longer runs and compliance coverage no longer counts it. Findings it raised in the past are kept \u2014 they still describe what was true when it ran.",
    showWithdrawn: "Show withdrawn rules",
    hideWithdrawn: "Hide withdrawn rules",
    withdrawnCount: "withdrawn",
    // The rest of what the catalogue holds and never showed.
    why: "Why this matters",
    howToFix: "How to fix it",
    showDetail: "Why and how to fix",
    hideDetail: "Hide",
  },
  compliance: {
    title: "Compliance",
    intro:
      "What CloudGuard's checks can evidence against the frameworks you report on \u2014 and, just as importantly, what they cannot.",
    notALegalClaim:
      "This is evidence, not a compliance verdict. A green control means specific misconfigurations were absent at the last scan; it is not a statement that a requirement is met in law or that an audit would pass.",
    coverage: "Assessable coverage",
    coverageHelp:
      "Share of the catalogued controls CloudGuard reached a conclusion on \u2014 pass or fail. Controls nothing checks, and controls it could not read, are excluded rather than counted as met.",
    controls: "controls",
    openFindings: "open findings",
    viewFramework: "View controls",
    scopeNote: "What this covers",
    ownWording:
      "Control titles are CloudGuard's own wording, not the published text. Follow the source link for authoritative definitions.",
    source: "Official source",
    noRules: "No rule checks this.",
    notAssessable: "Not observable by a scanner",
    notAssessableHelp:
      "This requirement is organizational, procedural or physical. No cloud posture scan can produce evidence for it.",
    evidenceFrom: "Evidence from",
    empty: "No frameworks in the catalogue.",
    backToFrameworks: "All frameworks",
    statusHelp: {
      FAILING: "At least one mapped rule is currently failing.",
      INCONCLUSIVE: "Nothing failing, but a mapped rule could not be evaluated. Not a pass.",
      PASSING: "Every mapped rule was evaluated conclusively and none is failing.",
      NOT_ASSESSED: "Rules map here, but no scan has produced a result yet.",
      NOT_COVERED: "No rule maps here. CloudGuard has nothing to say about it.",
    },
  },
  changes: {
    title: "Changes",
    intro:
      "The rest of the product says what is true in your environment now. This says what moved. A scan that finds nothing different writes nothing here, so a quiet week reads as a quiet week rather than as a wall of rows saying everything is still where it was.",
    empty: "Nothing moved in this window",
    emptyDetail:
      "No asset appeared, disappeared, or changed exposure, sensitivity or criticality in the period you are looking at. Widen the window to look further back.",
    emptyFiltered: "No changes of this kind in this window",
    emptyFilteredDetail:
      "Something may still have moved \u2014 clear the filter, or widen the window, to see the rest of the feed.",
    // Each kind said as a sentence about the asset, not as an enum name. "The
    // exposure changed" is a fact about a column; "became reachable from more
    // of the internet" is a fact the reader can act on.
    kind: {
      APPEARED: "Appeared",
      DISAPPEARED: "Disappeared",
      EXPOSURE_CHANGED: "Exposure changed",
      SENSITIVITY_CHANGED: "Data sensitivity changed",
      CRITICALITY_CHANGED: "Criticality changed",
    },
    appeared: "First seen in this environment",
    disappeared: "A scan that covered its scope did not see it",
    // The distinction that decides whether a DISAPPEARED row is history or a
    // job. The asset row is never deleted, so both readings are possible.
    stillMissing: "Still missing",
    returned: "Seen again since",
    worse: "Got worse",
    better: "Got better",
    windowLabel: "Look back",
    kindLabel: "Kind of change",
    windows: {
      1: "Last 24 hours",
      7: "Last 7 days",
      30: "Last 30 days",
      90: "Last 90 days",
    },
    allKinds: "All changes",
    count: "change",
    countPlural: "changes",
  },
  reports: {
    title: "Reports",
    intro:
      "The screens answer questions as you ask them. A report is the same evidence fixed to a moment, so it can be filed, sent to a board, or handed to an auditor \u2014 which is why every one of them prints when its evidence was collected and what could not be read.",
    executive: "Executive report",
    executiveDetail:
      "For a reader who does not touch Azure: the posture score and where it is going, the worst risks by what they would actually cost, and compliance coverage. Deliberately lists no findings \u2014 a summary that ends in a four-hundred-row table is a technical report with a cover page.",
    technical: "Technical report",
    technicalDetail:
      "Everything the executive report says, from the same numbers, and then every open finding worst first \u2014 the asset it was found on, when it was first seen, and what to change.",
    download: "Download PDF",
    preparing: "Preparing\u2026",
    preview: "Preview",
    // Regenerated on request rather than kept. Said plainly, because a
    // customer who expects a library of past reports should not have to
    // discover its absence.
    freshNote:
      "Reports are generated when you ask for one, from the evidence that exists at that moment. CloudGuard keeps no copies \u2014 a stored PDF outlives the evidence behind it, and there would be no honest way to say which of five was current.",
    // The one failure worth its own copy: the server is missing native
    // libraries, which is an operator problem and not something a retry fixes.
    noPdfTitle: "This server cannot produce PDFs",
    failed: "Could not generate the report",
  },
  settings: {
    title: "Settings",
    intro:
      "What CloudGuard knows about you and your environment that it could not find out by looking.",

    // The organization profile. A correction, not a statement: saving a name
    // must not clear a country nobody touched.
    orgTitle: "Organization",
    orgHelp: "How this organization is named in CloudGuard and on its reports.",
    orgName: "Name",
    orgIndustry: "Industry",
    orgCountry: "Country",
    orgCountryHelp: "Two-letter country code, e.g. AL.",
    orgSlug: "Identifier",
    orgSlugHelp:
      "Fixed when the organization was created and unchanged by a rename \u2014 it appears in stored references, so changing it would rename the thing rather than relabel it.",
    save: "Save changes",
    saving: "Saving\u2026",
    saved: "Saved",
    orgFailed: "Could not save the organization",
    // Only owners and admins may edit, and a reader who cannot should be told
    // why rather than meeting disabled fields with no explanation.
    orgReadOnly:
      "Your role can read this but not change it. An owner or an admin can edit the organization.",

    // The declarations. This is the part that changes what CloudGuard reports.
    contextTitle: "What your subscriptions are for",
    contextHelp:
      "CloudGuard scores a finding by what it would cost you \u2014 how critical the asset is, how sensitive its data, how exposed it is. It infers those from names and tags where it can, and inference is the weakest evidence it has. Anything you declare here beats it.",
    contextEmpty: "No subscriptions have been discovered yet",
    contextEmptyDetail:
      "Connect a cloud environment and CloudGuard will discover the subscriptions beneath it. There is nothing to describe until then.",
    environment: "Environment",
    criticality: "Criticality",
    dataSensitivity: "Data sensitivity",
    note: "Note",
    noteHelp: "Why this is what it is. Recorded with the declaration.",
    environmentPlaceholder: "production, staging, sandbox\u2026",
    // UNKNOWN is deliberately absent from these menus, and the copy says so:
    // it is CloudGuard's own word for "nothing said anything", so declaring it
    // would assert an absence that saying nothing already asserts.
    notDeclared: "Not declared",
    notDeclaredHelp:
      "Leaving a field unset is not the same as declaring it unknown \u2014 CloudGuard goes back to working it out for itself.",
    declaredBy: "Declared",
    declare: "Save declaration",
    clear: "Clear declaration",
    clearing: "Clearing\u2026",
    contextFailed: "Could not save the declaration",
    // The honest bit: a declaration is not retroactive.
    appliesNext:
      "Applied by the next evaluation of this subscription \u2014 the next scan, or a replay of its latest capture. Existing scores are left alone: a risk score is what a scan concluded, and rewriting stored numbers from a form would leave findings carrying figures no observation ever produced.",

    dangerTitle: "Delete this organization",
    dangerHelp:
      "Removes the organization and everything under it: connections, discovered subscriptions, assets, scans, findings, risks and audit history. There is no soft delete and no undo.",
    dangerConfirmLabel: "Type the organization name to confirm",
    delete: "Delete organization",
    deleting: "Deleting\u2026",
    deleteFailed: "Could not delete the organization",
    dangerOwnerOnly: "Only an owner can delete an organization.",
  },
  remediation: { title: "Remediation", empty: "No remediation tasks yet." },
  common: {
    loading: "Loading…",
    error: "Something went wrong",
    retry: "Try again",
    severity: "Severity",
    status: "Status",
    all: "All",
    unknown: "Unknown",
    never: "Never",
    back: "Back",
  },
} as const;

export type Strings = typeof en;
