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
        Control("A.5.16", "Identity management", "Organizational"),
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
        Control("A.8.2", "Privileged access rights", "Technological"),
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
        Control(
            "17",
            "Right to erasure",
            "Data subject rights",
            technically_assessable=False,
        ),
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
        Control(
            "PR.IP-4",
            "Backups of information are conducted, maintained and tested",
            "Protect",
        ),
        Control("PR.PT-1", "Audit records are determined, documented and reviewed", "Protect"),
        Control("PR.PT-4", "Communications and control networks are protected", "Protect"),
        Control("DE.AE-3", "Event data are collected and correlated", "Detect"),
        Control("DE.CM-1", "The network is monitored to detect events", "Detect"),
        # The functions the scope note above admits are out of reach, named
        # rather than merely mentioned. Listing only Protect and Detect made
        # this the one framework here that could report full coverage, which
        # ``test_catalogue_lists_controls_no_rule_covers`` correctly refused --
        # and the fault was the catalogue understating CSF rather than a
        # mapping being wrong. CSF holds over a hundred subcategories; these are
        # representative of the four functions a configuration reading cannot
        # speak to.
        Control(
            "ID.AM-1",
            "Physical devices and systems are inventoried",
            "Identify",
        ),
        Control(
            "ID.RA-1",
            "Asset vulnerabilities are identified and documented",
            "Identify",
        ),
        Control(
            "ID.GV-1",
            "An organizational security policy is established",
            "Identify",
            technically_assessable=False,
        ),
        Control(
            "RS.RP-1",
            "A response plan is executed during or after an incident",
            "Respond",
            technically_assessable=False,
        ),
        Control(
            "RC.RP-1",
            "A recovery plan is executed during or after an incident",
            "Recover",
            technically_assessable=False,
        ),
    ),
)

NIST_800_53 = Framework(
    id="NIST_800_53",
    name="NIST SP 800-53 Rev. 5",
    short_name="NIST 800-53",
    version="Rev. 5",
    authority="National Institute of Standards and Technology",
    url="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    summary=(
        "The control catalogue US federal systems are assessed against, and the "
        "one FedRAMP and CMMC are built on. Prescriptive where CSF is "
        "outcome-based, which is why an organization reporting against both "
        "needs them listed separately."
    ),
    scope_note=(
        "The technical controls in the AC, AU, CM, IA, SC and SI families that "
        "an Azure configuration reading can speak to. The publication holds "
        "over a thousand controls across twenty families; the personnel, "
        "training, incident response and physical families are absent because "
        "no scanner can observe them, and the families below are represented by "
        "their base controls rather than their enhancements."
    ),
    controls=(
        # --- Access Control -------------------------------------------------
        Control("AC-2", "Accounts are managed through their lifecycle", "Access Control"),
        Control("AC-3", "Access is enforced against an approved authorization", "Access Control"),
        Control("AC-6", "Privilege is held only where the work requires it", "Access Control"),
        Control("AC-17", "Remote access is authorized and controlled", "Access Control"),
        # --- Audit and Accountability ---------------------------------------
        Control("AU-2", "The events worth recording are decided and recorded", "Audit"),
        Control(
            "AU-6",
            "Audit records are reviewed for indications of harm",
            "Audit",
            technically_assessable=False,
        ),
        Control("AU-9", "Audit records are protected from alteration and loss", "Audit"),
        Control("AU-11", "Audit records are retained long enough to investigate", "Audit"),
        # --- Configuration Management ---------------------------------------
        Control("CM-6", "Systems run the configuration settings that were agreed", "Configuration"),
        Control(
            "CM-7",
            "Only the functions and ports the system needs are enabled",
            "Configuration",
        ),
        # --- Contingency Planning -------------------------------------------
        Control("CP-9", "System state is backed up and recoverable", "Contingency"),
        # --- Identification and Authentication ------------------------------
        Control("IA-2", "Users are uniquely identified and authenticated", "Identification"),
        Control("IA-5", "Authenticators are issued, protected and rotated", "Identification"),
        # --- Risk Assessment ------------------------------------------------
        Control("RA-5", "Systems are monitored for known vulnerabilities", "Risk Assessment"),
        # --- System and Communications Protection ---------------------------
        Control("SC-7", "Traffic at the system boundary is controlled", "System Protection"),
        Control("SC-8", "Information in transit is protected", "System Protection"),
        Control("SC-12", "Cryptographic keys are established and managed", "System Protection"),
        Control("SC-28", "Information at rest is protected", "System Protection"),
        # --- System and Information Integrity -------------------------------
        Control("SI-2", "Flaws are identified, reported and corrected", "System Integrity"),
        Control("SI-4", "The system is monitored for attacks and indicators", "System Integrity"),
        # --- Families no configuration reading can reach --------------------
        # Listed rather than omitted, for the reason at the top of this file: a
        # catalogue of only what CloudGuard checks would report full coverage
        # for ever. These are the families an assessor will ask about and this
        # product will never answer.
        Control(
            "AT-2",
            "People are trained on the risks their work carries",
            "Awareness",
            technically_assessable=False,
        ),
        Control(
            "IR-4",
            "Incidents are handled from detection to recovery",
            "Incident Response",
            technically_assessable=False,
        ),
        Control(
            "PS-4",
            "Access is removed when someone leaves",
            "Personnel",
            technically_assessable=False,
        ),
        Control(
            "PE-3",
            "Physical access to the facility is controlled",
            "Physical",
            technically_assessable=False,
        ),
    ),
)

SOC2 = Framework(
    id="SOC2",
    name="SOC 2 Trust Services Criteria",
    short_name="SOC 2",
    version="2017 (rev. 2022)",
    authority="American Institute of Certified Public Accountants",
    url="https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
    summary=(
        "What an auditor tests during a SOC 2 examination. Not a configuration "
        "standard: most criteria are about whether an organization has a "
        "control and operates it, and a scanner can only ever be evidence "
        "toward the subset that lands in a cloud configuration."
    ),
    scope_note=(
        "The Common Criteria concerning logical access and monitoring, plus the "
        "availability criterion covering recovery. CC1 to CC5 -- control "
        "environment, communication, risk assessment, monitoring and control "
        "activities -- are about how an organization is run and are listed here "
        "unassessable rather than omitted. Nothing on this page is an opinion "
        "about a SOC 2 examination, which only a licensed firm can issue."
    ),
    controls=(
        # --- Common Criteria: logical and physical access -------------------
        Control(
            "CC6.1",
            "Access to systems and data is restricted to those authorized",
            "Logical Access",
        ),
        Control(
            "CC6.2",
            "Access is granted on authorization and removed when it ends",
            "Logical Access",
        ),
        Control("CC6.3", "Access rights follow least privilege and are reviewed", "Logical Access"),
        Control(
            "CC6.6",
            "The system is protected against access from outside its boundary",
            "Logical Access",
        ),
        Control(
            "CC6.7",
            "Information is protected as it moves and as it is stored",
            "Logical Access",
        ),
        Control(
            "CC6.8",
            "Unauthorized or malicious software is prevented and detected",
            "Logical Access",
        ),
        # --- Common Criteria: system operations -----------------------------
        Control(
            "CC7.1",
            "Configuration is monitored for change and for vulnerability",
            "Operations",
        ),
        Control(
            "CC7.2",
            "The system is monitored for anomalies that indicate an incident",
            "Operations",
        ),
        Control(
            "CC7.3",
            "Detected events are evaluated to decide whether they are incidents",
            "Operations",
            technically_assessable=False,
        ),
        Control(
            "CC7.4",
            "Incidents are responded to and recovered from",
            "Operations",
            technically_assessable=False,
        ),
        # --- Common Criteria: change and risk -------------------------------
        Control(
            "CC8.1",
            "Changes are authorized, designed, tested and approved",
            "Change Management",
            technically_assessable=False,
        ),
        Control(
            "CC9.1",
            "Risks from business disruption are identified and mitigated",
            "Risk Mitigation",
            technically_assessable=False,
        ),
        # --- Availability ---------------------------------------------------
        Control("A1.2", "Recovery of the environment is provided for and tested", "Availability"),
        # --- The criteria a scanner has nothing to say about ----------------
        # An organization is judged on all of these and CloudGuard reads none of
        # them. Listing them is the difference between a page that reports
        # honest partial coverage and one that implies a SOC 2 report is a
        # configuration problem.
        Control(
            "CC1.1",
            "The organization demonstrates a commitment to integrity",
            "Control Environment",
            technically_assessable=False,
        ),
        Control(
            "CC1.4",
            "The organization attracts and retains competent people",
            "Control Environment",
            technically_assessable=False,
        ),
        Control(
            "CC2.1",
            "Quality information is used to support the controls",
            "Communication",
            technically_assessable=False,
        ),
        Control(
            "CC2.2",
            "Responsibilities for security are communicated internally",
            "Communication",
            technically_assessable=False,
        ),
        Control(
            "CC3.1",
            "Objectives are set clearly enough for risks to be judged against",
            "Risk Assessment",
            technically_assessable=False,
        ),
        Control(
            "CC3.2",
            "Risks to the objectives are identified and analysed",
            "Risk Assessment",
            technically_assessable=False,
        ),
        Control(
            "CC3.3",
            "The potential for fraud is considered when assessing risk",
            "Risk Assessment",
            technically_assessable=False,
        ),
        Control(
            "CC4.1",
            "The controls are evaluated for whether they are working",
            "Monitoring",
            technically_assessable=False,
        ),
        Control(
            "CC4.2",
            "Control deficiencies are communicated to those who can act",
            "Monitoring",
            technically_assessable=False,
        ),
        Control(
            "CC5.1",
            "Control activities are selected to bring risks to an acceptable level",
            "Control Activities",
            technically_assessable=False,
        ),
        Control(
            "CC5.2",
            "Controls over technology are selected and developed",
            "Control Activities",
            technically_assessable=False,
        ),
        Control(
            "CC5.3",
            "Control activities are deployed through policies people follow",
            "Control Activities",
            technically_assessable=False,
        ),
        Control(
            "CC7.5",
            "The organization recovers from identified incidents",
            "Operations",
            technically_assessable=False,
        ),
        Control(
            "CC9.2",
            "Risks carried by vendors and business partners are managed",
            "Risk Mitigation",
            technically_assessable=False,
        ),
    ),
)

PCI_DSS = Framework(
    id="PCI_DSS_4",
    name="PCI DSS v4.0.1",
    short_name="PCI DSS",
    version="4.0.1",
    authority="PCI Security Standards Council",
    url="https://www.pcisecuritystandards.org/document_library/",
    summary=(
        "The card brands' requirements for anyone who stores, processes or "
        "transmits cardholder data. Unlike the frameworks above it is "
        "contractual rather than advisory: a merchant is assessed against it "
        "and can lose the ability to take payments."
    ),
    scope_note=(
        "PCI applies to the cardholder data environment, and CloudGuard does "
        "not know which of your resources are in it. That is the caveat that "
        "matters most on this page. Scope is a decision a QSA makes with you "
        "about network segmentation, data flows and where card data actually "
        "goes -- and every number here is computed over the whole subscription "
        "instead. A resource group holding no card data is counted the same as "
        "the one that does. Read these as configuration evidence you can hand "
        "to an assessor for the systems they have already scoped in, never as "
        "a position on requirements 3 or 4 for the environment as a whole. The "
        "requirements below are the technical ones a configuration reading "
        "reaches; the standard holds several hundred."
    ),
    controls=(
        # --- 1. Network security controls -----------------------------------
        Control(
            "1.2.1",
            "Network security controls are configured and enforced",
            "Network Security",
        ),
        Control(
            "1.3.1",
            "Inbound traffic to the cardholder data environment is restricted",
            "Network Security",
        ),
        Control(
            "1.4.1",
            "Connections between trusted and untrusted networks are controlled",
            "Network Security",
        ),
        # --- 2. Secure configuration ----------------------------------------
        Control(
            "2.2.1",
            "System components are configured to a hardened standard",
            "Secure Configuration",
        ),
        # --- 3. Protect stored account data ---------------------------------
        Control(
            "3.5.1",
            "Stored account data is rendered unreadable",
            "Stored Data",
        ),
        Control(
            "3.6.1",
            "Cryptographic keys are protected against disclosure and misuse",
            "Stored Data",
        ),
        # --- 4. Protect data in transit -------------------------------------
        Control(
            "4.2.1",
            "Strong cryptography protects account data in transit",
            "Data In Transit",
        ),
        # --- 5. Malicious software ------------------------------------------
        Control(
            "5.2.1",
            "Systems are protected against malicious software",
            "Malware",
        ),
        # --- 6. Secure systems and software ---------------------------------
        Control(
            "6.3.3",
            "Known vulnerabilities are corrected by applying security patches",
            "Secure Software",
        ),
        Control(
            "6.5.1",
            "Changes to system components follow a change control process",
            "Secure Software",
            technically_assessable=False,
        ),
        # --- 7. Access by business need to know -----------------------------
        Control(
            "7.2.1",
            "Access is granted on business need and least privilege",
            "Access Control",
        ),
        Control(
            "7.2.2",
            "Privileges assigned are the least the role requires",
            "Access Control",
        ),
        # --- 8. Identify and authenticate -----------------------------------
        Control(
            "8.2.1",
            "Every user is identified by a unique account",
            "Authentication",
        ),
        Control(
            "8.3.1",
            "Access is authenticated by a strong factor",
            "Authentication",
        ),
        Control(
            "8.4.2",
            "Multi-factor authentication is required for administrative access",
            "Authentication",
        ),
        # --- 9. Physical access ---------------------------------------------
        Control(
            "9.1.1",
            "Physical access to cardholder data is restricted",
            "Physical Access",
            technically_assessable=False,
        ),
        # --- 10. Log and monitor --------------------------------------------
        Control(
            "10.2.1",
            "Audit logs record access to system components and card data",
            "Logging",
        ),
        Control(
            "10.3.2",
            "Audit logs are protected from alteration and destruction",
            "Logging",
        ),
        Control(
            "10.5.1",
            "Audit history is retained long enough to investigate",
            "Logging",
        ),
        # --- 11. Test security ----------------------------------------------
        Control(
            "11.3.1",
            "Internal vulnerability scans are run and findings resolved",
            "Security Testing",
        ),
        Control(
            "11.4.1",
            "Penetration testing is performed and findings addressed",
            "Security Testing",
            technically_assessable=False,
        ),
        # --- 12. Organizational policy --------------------------------------
        Control(
            "12.1.1",
            "An information security policy is established and maintained",
            "Policy",
            technically_assessable=False,
        ),
        Control(
            "12.10.1",
            "An incident response plan exists and is exercised",
            "Policy",
            technically_assessable=False,
        ),
    ),
)

FRAMEWORKS: tuple[Framework, ...] = (
    CIS_AZURE,
    ISO_27001,
    GDPR,
    NIST_CSF,
    NIST_800_53,
    SOC2,
    PCI_DSS,
)


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
