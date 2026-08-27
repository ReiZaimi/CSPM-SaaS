"""The framework catalogue -- what the control identifiers on rules mean.

Rules already carry framework references (``rules.compliance_mappings``), but a
reference is only half of a mapping: ``A.8.20`` tells a user nothing on its own.
This module is the other half, and it is **data, not logic**. Nothing here
branches on a framework, and no rule ever imports it -- which is what keeps
PRODUCT_SPEC.md requirement 15 true while still being able to render a coverage
page.

Three deliberate choices, each of which changes what the coverage number means:

**Control titles are CloudGuard's own words.** CIS Benchmarks and ISO/IEC 27001
are copyrighted works under licences that restrict redistribution of their text;
GDPR is public law but is quoted in summary here for consistency. So every title
below is a short descriptor written for this product, not the official wording.
The identifiers are the durable part -- follow ``url`` for authoritative text.

**Uncovered areas are in the catalogue on purpose.** A catalogue containing only
the controls CloudGuard happens to check would report 100% coverage forever,
which is worse than reporting nothing. Entries a rule cannot reach are listed
too, and resolve to NOT_COVERED.

**Gaps are listed at whatever resolution is honest.** Where CloudGuard covers a
specific control it is listed specifically; where a whole area is unchecked, the
benchmark's own section number is listed rather than inventing leaf numbers to
mark absent. A wrong control number in a compliance view is worse than a coarse
one.

None of this produces a compliance claim. It produces evidence, mapped to a
requirement, attributed to a framework -- the chain in ROADMAP.md, no further.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    """One requirement a rule can produce evidence toward."""

    id: str
    title: str
    group: str
    # False where the requirement is organizational, procedural or physical --
    # something no scanner can observe. Kept distinct from "not covered yet":
    # one is a backlog item, the other never will be, and a user deciding where
    # to spend effort needs to know which is which.
    technically_assessable: bool = True


@dataclass(frozen=True)
class Framework:
    id: str
    name: str
    short_name: str
    version: str
    authority: str
    url: str
    summary: str
    # What subset of the published framework this catalogue represents. Shown
    # in the UI verbatim, because a coverage percentage against an unstated
    # denominator is a number that misleads.
    scope_note: str
    controls: tuple[Control, ...]

    def control(self, control_id: str) -> Control | None:
        return next((c for c in self.controls if c.id == control_id), None)


CIS_AZURE = Framework(
    id="CIS_AZURE_2.0",
    name="CIS Microsoft Azure Foundations Benchmark",
    short_name="CIS Azure",
    version="2.0.0",
    authority="Center for Internet Security",
    url="https://www.cisecurity.org/benchmark/azure",
    summary=(
        "Consensus-built configuration baseline for Azure subscriptions. The "
        "closest thing this product has to a peer: prescriptive, technical, and "
        "checkable without interviewing anybody."
    ),
    scope_note=(
        "Covers the benchmark sections a posture scanner can reach. Sections "
        "listed without a leaf number are areas CloudGuard runs no checks in at "
        "all, shown so the gap is visible rather than absent."
    ),
    controls=(
        Control(
            "1.1.1", "Security defaults enabled on the directory", "Identity and Access Management"
        ),
        Control(
            "1.1.2",
            "Multi-factor authentication required for privileged users",
            "Identity and Access Management",
        ),
        Control(
            "1.1.3",
            "Multi-factor authentication required for non-privileged users",
            "Identity and Access Management",
        ),
        Control(
            "1.21",
            "No excessive or custom subscription administrator roles",
            "Identity and Access Management",
        ),
        Control(
            "2", "Microsoft Defender for Cloud plans and alerting", "Microsoft Defender for Cloud"
        ),
        Control("3.1", "Secure transfer required on storage accounts", "Storage Accounts"),
        Control("3.7", "Public blob access disabled", "Storage Accounts"),
        Control("3.8", "Storage account network access restricted by default", "Storage Accounts"),
        Control("3.15", "Minimum TLS version enforced on storage accounts", "Storage Accounts"),
        Control("4.1.1", "Public network access disabled on database servers", "Database Services"),
        Control(
            "4.1.2", "Database firewall rules do not permit all addresses", "Database Services"
        ),
        Control(
            "5.1.1", "Diagnostic settings capture subscription activity", "Logging and Monitoring"
        ),
        Control("5.3", "Diagnostic logs enabled on supported resources", "Logging and Monitoring"),
        Control("6.1", "RDP not reachable from the internet", "Networking"),
        Control("6.2", "SSH not reachable from the internet", "Networking"),
        Control("6.5", "Network watcher and unrestricted inbound rules reviewed", "Networking"),
        Control("7.1", "Virtual machine disk encryption", "Virtual Machines"),
        Control("8", "Key Vault access policies, expiry and purge protection", "Key Vault"),
        Control("9", "App Service authentication, TLS and HTTPS enforcement", "AppService"),
    ),
)

ISO_27001 = Framework(
    id="ISO_27001",
    name="ISO/IEC 27001:2022 Annex A",
    short_name="ISO 27001",
    version="2022",
    authority="ISO/IEC",
    url="https://www.iso.org/standard/27001",
    summary=(
        "The control set an ISMS certification audits against. Most of it is "
        "about people and process; the technological controls in A.8 are where "
        "a cloud scanner has anything to say."
    ),
    scope_note=(
        "A subset of Annex A: the controls a cloud posture scan can produce "
        "evidence toward, plus nearby controls it cannot, marked as such. The "
        "other Annex A controls are outside anything this product observes."
    ),
    controls=(
        Control("A.5.10", "Acceptable use of information and associated assets", "Organizational"),
        Control("A.5.15", "Access control", "Organizational"),
        Control("A.5.17", "Authentication information", "Organizational"),
        Control("A.5.18", "Access rights", "Organizational"),
        Control(
            "A.5.30",
            "ICT readiness for business continuity",
            "Organizational",
            technically_assessable=False,
        ),
        Control(
            "A.6.3",
            "Information security awareness and training",
            "People",
            technically_assessable=False,
        ),
        Control("A.8.3", "Information access restriction", "Technological"),
        Control("A.8.8", "Management of technical vulnerabilities", "Technological"),
        Control("A.8.13", "Information backup", "Technological"),
        Control("A.8.15", "Logging", "Technological"),
        Control("A.8.16", "Monitoring activities", "Technological"),
        Control("A.8.20", "Networks security", "Technological"),
        Control("A.8.22", "Segregation of networks", "Technological"),
        Control("A.8.23", "Web filtering", "Technological"),
        Control("A.8.24", "Use of cryptography", "Technological"),
    ),
)

GDPR = Framework(
    id="GDPR",
    name="General Data Protection Regulation",
    short_name="GDPR",
    version="Regulation (EU) 2016/679",
    authority="European Union",
    url="https://eur-lex.europa.eu/eli/reg/2016/679/oj",
    summary=(
        "A law, not a control framework. Article 32 requires security measures "
        "appropriate to the risk, and that is the only place a scanner can "
        "contribute — as evidence a controller cites, never as a verdict."
    ),
    scope_note=(
        "Only the articles with a technical-measures component. A green result "
        "here means specific misconfigurations were absent at the last scan. It "
        "is not, and cannot be, a statement about lawful processing."
    ),
    controls=(
        Control("5(1)(f)", "Integrity and confidentiality of personal data", "Principles"),
        Control("5(2)", "Accountability — demonstrating compliance", "Principles"),
        Control("17", "Right to erasure", "Data subject rights", technically_assessable=False),
        Control("25", "Data protection by design and by default", "Controller obligations"),
        Control(
            "30",
            "Records of processing activities",
            "Controller obligations",
            technically_assessable=False,
        ),
        Control(
            "32(1)(a)", "Pseudonymisation and encryption of personal data", "Security of processing"
        ),
        Control(
            "32(1)(b)",
            "Ongoing confidentiality, integrity and availability",
            "Security of processing",
        ),
        Control("32(1)(c)", "Restoring availability after an incident", "Security of processing"),
        Control("32(1)(d)", "Regular testing and evaluation of measures", "Security of processing"),
        Control("33", "Notifying a personal data breach", "Breach obligations"),
        Control(
            "44",
            "General principle for international transfers",
            "Transfers",
            technically_assessable=False,
        ),
    ),
)

NIST_CSF = Framework(
    id="NIST_CSF",
    name="NIST Cybersecurity Framework",
    short_name="NIST CSF",
    version="1.1",
    authority="National Institute of Standards and Technology",
    url="https://www.nist.gov/cyberframework",
    summary=(
        "Outcome-based subcategories rather than prescriptive settings. Useful "
        "as a common vocabulary when an organization already reports against it."
    ),
    scope_note=(
        "The Protect and Detect subcategories CloudGuard's rules speak to. The "
        "Identify, Respond and Recover functions are largely organizational."
    ),
    controls=(
        Control("PR.AC-1", "Identities and credentials are managed", "Protect"),
        Control("PR.AC-3", "Remote access is managed", "Protect"),
        Control("PR.AC-4", "Access permissions follow least privilege", "Protect"),
        Control("PR.AC-5", "Network integrity is protected and segregated", "Protect"),
        Control("PR.AC-7", "Authentication is proportionate to risk", "Protect"),
        Control("PR.DS-1", "Data at rest is protected", "Protect"),
        Control("PR.DS-2", "Data in transit is protected", "Protect"),
        Control("PR.DS-5", "Protections against data leaks are implemented", "Protect"),
        Control("PR.PT-1", "Audit records are determined, documented and reviewed", "Protect"),
        Control("PR.PT-4", "Communications and control networks are protected", "Protect"),
        Control("DE.AE-3", "Event data are collected and correlated", "Detect"),
        Control("DE.CM-1", "The network is monitored to detect events", "Detect"),
    ),
)

FRAMEWORKS: tuple[Framework, ...] = (CIS_AZURE, ISO_27001, GDPR, NIST_CSF)


def get_framework(framework_id: str) -> Framework | None:
    return next((f for f in FRAMEWORKS if f.id == framework_id), None)


def _assert_unique() -> None:
    """A duplicate framework or control id would make coverage double-count."""
    framework_ids: set[str] = set()
    for framework in FRAMEWORKS:
        if framework.id in framework_ids:
            raise RuntimeError(f"Duplicate framework id in catalogue: {framework.id}")
        framework_ids.add(framework.id)

        control_ids: set[str] = set()
        for control in framework.controls:
            if control.id in control_ids:
                raise RuntimeError(f"Duplicate control id in {framework.id}: {control.id}")
            control_ids.add(control.id)


_assert_unique()
