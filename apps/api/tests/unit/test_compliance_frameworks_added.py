"""NIST SP 800-53, SOC 2 and PCI DSS, and the claims none of them may make.

Both were added as mapping layers over the rules that already existed. No rule
was written for them, none runs twice, and no business logic anywhere branches
on a framework name -- which is the property that lets a sixth catalogue cost a
data change rather than a scanning engine.

The tests that matter here are the ones about overreach, and each of the three
overreaches differently.

SOC 2 is an examination of an organization: most criteria are about whether it
*has* a control and operates it, so a configuration reading is evidence toward a
fraction of them, and only a licensed firm issues the opinion.

PCI is worse, because its number looks credible and is computed over the wrong
denominator. The standard applies to the cardholder data environment, and
CloudGuard has no idea which resources are in it -- scope is a decision a QSA
makes with the merchant about segmentation and data flows. Every figure on that
page covers the whole subscription instead.

Saying so in the catalogue is not decoration. It is the difference between
honest partial coverage and a page somebody hands to an assessor as though it
settled something.
"""

from app.compliance.catalog import get_framework
from app.rules.registry import RULE_REGISTRY

NIST = "NIST_800_53"
SOC2 = "SOC2"
PCI = "PCI_DSS_4"

ADDED = (NIST, SOC2, PCI)


def framework(framework_id: str):
    found = get_framework(framework_id)
    assert found is not None, f"{framework_id} is not in the catalogue"
    return found


class TestTheyAreMappingsRatherThanEngines:
    def test_every_rule_maps_to_all_of_them(self) -> None:
        """A rule that reached one framework and not another would produce two
        coverage numbers over the same evidence, and only one of them right."""
        for framework_id in ADDED:
            unmapped = [
                rule.rule_id
                for rule in RULE_REGISTRY
                if framework_id not in (rule.compliance_mappings or {})
            ]
            assert unmapped == [], (
                f"these rules produce evidence nothing attributes to "
                f"{framework_id}: {unmapped}"
            )

    def test_no_rule_was_added_for_any_of_them(self) -> None:
        """The architectural claim, checked rather than asserted in prose. A
        framework is a mapping over the rules that exist; a rule written *for*
        a framework would be the same technical check duplicated per standard,
        which is what the compliance layer exists to avoid."""
        by_id = {rule.rule_id for rule in RULE_REGISTRY}

        assert not [r for r in by_id if any(s in r for s in ("NIST", "SOC", "PCI"))]

    def test_a_single_rule_reaches_every_framework(self) -> None:
        """One finding, six views. AZ-ID-001 is the canonical example: an
        administrator without a second factor is an identity control everywhere,
        and it is evaluated once."""
        mfa = next(r for r in RULE_REGISTRY if r.rule_id == "AZ-ID-001")

        assert set(mfa.compliance_mappings) >= {
            "CIS_AZURE_2.0",
            "ISO_27001",
            "NIST_CSF",
            "GDPR",
            *ADDED,
        }


class TestNeitherClaimsMoreThanItCan:
    def test_each_lists_controls_no_rule_covers(self) -> None:
        """A catalogue holding only what CloudGuard checks reports full
        coverage for ever, which is worse than reporting nothing."""
        for framework_id in ADDED:
            catalogue = framework(framework_id)
            covered = {
                control_id
                for rule in RULE_REGISTRY
                for control_id in (rule.compliance_mappings or {}).get(framework_id, [])
            }
            uncovered = [c.id for c in catalogue.controls if c.id not in covered]
            assert uncovered, f"{framework_id} claims every control is covered"

    def test_each_marks_the_controls_no_scanner_can_observe(self) -> None:
        """Distinct from "not covered yet". One is a backlog item and the other
        never will be, and somebody deciding where to spend effort needs to
        know which is which."""
        for framework_id in ADDED:
            unassessable = [
                c for c in framework(framework_id).controls if not c.technically_assessable
            ]
            assert unassessable, (
                f"{framework_id} implies a configuration reading could satisfy "
                "every one of its controls"
            )

    def test_soc2_is_mostly_beyond_a_scanner_and_says_so(self) -> None:
        """The specific overreach worth naming. SOC 2 is an examination of an
        organization, and the majority of its criteria are about how that
        organization is run."""
        catalogue = framework(SOC2)
        assessable = [c for c in catalogue.controls if c.technically_assessable]

        assert len(assessable) < len(catalogue.controls) / 2
        assert "licensed firm" in catalogue.scope_note

    def test_no_summary_promises_compliance(self) -> None:
        """CloudGuard produces evidence attributed to a requirement. It does not
        issue an opinion, and the words on the page must not read like one."""
        for framework_id in ADDED:
            catalogue = framework(framework_id)
            words = f"{catalogue.summary} {catalogue.scope_note}".lower()

            assert "compliant" not in words
            assert "certified" not in words

    def test_the_scope_note_says_what_subset_is_represented(self) -> None:
        """A coverage figure against an unstated denominator is a number that
        misleads. 800-53 holds over a thousand controls; this catalogue holds
        two dozen, and the page says so."""
        for framework_id in ADDED:
            assert len(framework(framework_id).scope_note) > 120


class TestTitlesAreCloudGuardsOwnWords:
    def test_no_control_title_is_a_bare_identifier(self) -> None:
        """The titles are written for this product rather than reproduced.
        AICPA's Trust Services Criteria are copyrighted; 800-53 is a US
        Government work and free to quote, and is described in the same house
        style anyway so the two pages read alike."""
        for framework_id in ADDED:
            for control in framework(framework_id).controls:
                assert len(control.title.split()) >= 4, control.id
                assert control.title[0].isupper()

    def test_every_control_carries_a_group(self) -> None:
        """The grouping is what the framework page renders sections from, and a
        control with none would render outside every heading."""
        for framework_id in ADDED:
            for control in framework(framework_id).controls:
                assert control.group


class TestPciSaysWhoseScopeItIsNot:
    """PCI's number looks credible and is computed over the wrong denominator.

    The standard applies to the cardholder data environment. CloudGuard reads a
    subscription and has no idea which of its resources are in that environment
    -- scope is a decision a QSA makes with the merchant about segmentation and
    data flows. A resource group holding no card data is counted here exactly
    like the one that does.

    This is the most consequential caveat in the catalogue, because PCI is
    contractual: a merchant assessed against it can lose the ability to take
    payments, and a page that implied it had assessed them would be doing harm
    rather than merely overreaching.
    """

    def test_the_scope_note_says_cloudguard_does_not_know_the_scope(self) -> None:
        note = framework(PCI).scope_note.lower()

        assert "cardholder data environment" in note
        assert "does not know" in note

    def test_it_covers_the_technical_requirements_and_says_it_is_a_subset(
        self,
    ) -> None:
        """The standard holds several hundred requirements. This catalogue holds
        two dozen, and a coverage figure against an unstated denominator is a
        number that misleads."""
        assert "several hundred" in framework(PCI).scope_note

    def test_the_requirements_no_scanner_reaches_are_present(self) -> None:
        """Physical access, penetration testing, policy and incident response.
        An assessor asks about all four and this product answers none of them.
        """
        unassessable = {
            c.id for c in framework(PCI).controls if not c.technically_assessable
        }

        assert {"9.1.1", "11.4.1", "12.1.1", "12.10.1"} <= unassessable

    def test_the_malware_and_patching_gaps_were_closed_by_collection(self) -> None:
        """These three were the backlog, and reading Defender for Cloud's
        assessments is what closed them.

        Worth pinning as the shape of how a gap closes here: not by writing a
        rule that asserts something CloudGuard cannot see, but by collecting the
        evidence and then judging it. Anti-malware state and patch level are
        facts only the machine knows, and Defender is what knows the machine.
        """
        covered = {
            control_id
            for rule in RULE_REGISTRY
            for control_id in (rule.compliance_mappings or {}).get(PCI, [])
        }

        assert {"5.2.1", "6.3.3", "11.3.1"} <= covered

    def test_what_remains_uncovered_is_still_uncovered(self) -> None:
        """The guard the test above replaced. A framework whose every control
        is covered reports full coverage for ever, so PCI must still name what
        CloudGuard cannot reach -- and 2.2.1, a hardened configuration
        standard, is a real backlog item rather than a never."""
        catalogue = framework(PCI)
        covered = {
            control_id
            for rule in RULE_REGISTRY
            for control_id in (rule.compliance_mappings or {}).get(PCI, [])
        }
        uncovered = [c.id for c in catalogue.controls if c.id not in covered]

        assert uncovered
        baseline = catalogue.control("2.2.1")
        assert baseline is not None and baseline.technically_assessable
        assert "2.2.1" in uncovered

