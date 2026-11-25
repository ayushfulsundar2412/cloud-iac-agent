import pytest
from pydantic import ValidationError

from app.findings import RULES
from app.reporting import Explanation, build_report, llm_explanation, render_markdown
from app.reporting.builder import describe_evidence
from app.reporting.knowledge import KNOWLEDGE

SCAN = {"id": 1, "account_id": "123456789012", "region": "us-east-1"}
SSH = {"inbound": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}]}


def res(rid, rtype, config, name=None, aws_id=None):
    return {"id": rid, "resource_type": rtype, "resource_id": aws_id or f"x-{rid}",
            "name": name, "app": "shared", "config": config}


def sample():
    return [
        res(1, "security_group", SSH, name="open-ssh"),
        res(2, "ebs_volume", {"state": "available", "volume_type": "gp2", "size_gb": 100}, name="old-disk"),
        res(3, "elastic_ip", {"associated": False}, name="idle-ip"),
    ]


class Scripted:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, system, user, json_schema=None):
        self.calls.append(user)
        return self.replies.pop(0)


GOOD = ('{"summary": "SSH is open to everyone.", "why_it_matters": "Anyone can try to log in.", '
        '"suggested_fix": "Limit it to the office range."}')


def test_every_rule_has_written_knowledge():
    assert set(KNOWLEDGE) == set(RULES)
    for entry in KNOWLEDGE.values():
        assert entry["why"] and entry["fix"]
        assert "$" not in entry["why"] + entry["fix"]


def test_evidence_is_readable():
    from app.findings import evaluate
    finding = evaluate([res(1, "security_group", SSH)])[0]
    assert describe_evidence(finding) == "SSH (ports 22-22) open to 0.0.0.0/0"


def test_report_counts_and_savings_without_double_counting():
    report = build_report(SCAN, sample())
    summary = report["summary"]
    assert summary["findings"] == 4
    assert summary["by_severity"] == {"high": 1, "medium": 1, "low": 2}
    assert summary["by_category"] == {"risk": 1, "cost": 3}
    # the disk is unattached (10.00) and gp2 (2.00): only 10.00 counts, plus 3.65 for the IP
    assert summary["savings"]["total_usd"] == 13.65
    assert summary["savings"]["estimated"] == 3


def test_other_regions_get_no_dollar_figures():
    report = build_report({**SCAN, "region": "eu-west-1"}, sample())
    savings = report["summary"]["savings"]
    assert savings["total_usd"] == 0
    assert savings["estimated"] == 0
    assert "not estimated" in render_markdown(report)


def test_upper_bound_savings_are_marked():
    resources = [res(1, "ebs_snapshot", {"age_days": 400, "size_gb": 200}, name="old-snap")]
    report = build_report(SCAN, resources)
    assert report["summary"]["savings"]["includes_upper_bounds"] is True
    assert "up to $10.00" in render_markdown(report)


def test_coverage_lists_partly_checked_and_unsupported_types():
    resources = [
        res(1, "security_group", {}, name="a"),
        res(2, "security_group", {"inbound": []}, name="b"),
        res(3, "vpc", {}, name="v"),
    ]
    coverage = build_report(SCAN, resources)["coverage"]
    assert coverage["fully_checked"] == 1
    assert [p["id"] for p in coverage["partly_checked"]] == [1]
    assert coverage["partly_checked"][0]["missing"] == ["inbound"]
    assert coverage["no_rules_for_type"] == {"vpc": 1}


def test_markdown_has_the_key_sections():
    text = render_markdown(build_report(SCAN, sample(), generated_at="test run"))
    for expected in ("# Cloud estate report", "## Summary", "## Risk findings", "## Cost findings",
                     "$13.65", "Admin ports are open to the internet",
                     "## What this report could not check", "test run"):
        assert expected in text


def test_an_empty_estate_still_renders():
    text = render_markdown(build_report(SCAN, []))
    assert "Findings: 0" in text
    assert "None found." in text


def test_untrusted_names_cannot_become_links_or_tags():
    evil = "[click me](http://evil.example) <script>"
    text = render_markdown(build_report(SCAN, [res(1, "security_group", SSH, name=evil)]))
    assert f"`{evil}`" in text          # shown as inert text inside a code span
    assert "<script>" not in text.replace(f"`{evil}`", "")


def test_the_report_uses_llm_text_when_it_is_valid():
    def explainer(finding, resource):
        return Explanation(summary="SSH is open to everyone.", why_it_matters="Anyone can try.",
                           suggested_fix="Limit it.")
    item = build_report(SCAN, sample(), explainer=explainer)["findings"][0]
    assert item["explained_by"] == "llm"
    assert item["why_it_matters"] == "Anyone can try."


def test_a_failing_explainer_falls_back_to_the_written_text():
    def broken(finding, resource):
        raise RuntimeError("model is down")
    item = build_report(SCAN, sample(), explainer=broken)["findings"][0]
    assert item["explained_by"] == "fixed text"
    assert item["why_it_matters"] == KNOWLEDGE["sg-admin-open"]["why"]


def test_model_text_cannot_inject_links():
    def explainer(finding, resource):
        return Explanation(summary="See [this](http://evil.example)", why_it_matters="x", suggested_fix="y")
    text = render_markdown(build_report(SCAN, sample(), explainer=explainer))
    assert "[this]" not in text


def test_explanations_may_not_contain_money():
    with pytest.raises(ValidationError):
        Explanation(summary="This saves $5", why_it_matters="x", suggested_fix="y")


def test_llm_explanation_is_checked_and_retried():
    from app.findings import evaluate
    finding = evaluate([res(1, "security_group", SSH)])[0]
    backend = Scripted(["not json", GOOD])
    result = llm_explanation(finding, sample()[0], backend=backend)
    assert result.summary == "SSH is open to everyone."
    assert len(backend.calls) == 2


def test_llm_explanation_gives_up_quietly():
    from app.findings import evaluate
    finding = evaluate([res(1, "security_group", SSH)])[0]
    assert llm_explanation(finding, sample()[0], backend=Scripted(["no", "no", "no"])) is None


def test_the_prompt_never_contains_the_resource_name():
    from app.findings import evaluate
    finding = evaluate([res(1, "security_group", SSH, name="SECRET-NAME")])[0]
    backend = Scripted([GOOD])
    llm_explanation(finding, res(1, "security_group", SSH, name="SECRET-NAME"), backend=backend)
    assert "SECRET-NAME" not in backend.calls[0]