import json
from pathlib import Path

import pytest

from app.pipeline import run_pipeline

SAMPLE = Path(__file__).parent.parent / "sample" / "estate.json"


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    return run_pipeline(SAMPLE, tmp_path_factory.mktemp("demo"), generated_at="test run")


def read(run, relative):
    return (run.out_dir / relative).read_text(encoding="utf-8")


def test_the_pipeline_writes_every_expected_file(run):
    expected = [
        "report.md", "report.json", "terraform/fixes.diff", "terraform/GAPS.txt",
        "terraform/current/APPLY_ORDER.md",
        "terraform/current/shared/main.tf", "terraform/current/billing/main.tf",
        "terraform/current/website/main.tf",
        "terraform/proposed/shared/main.tf", "terraform/proposed/billing/main.tf",
        "terraform/proposed/website/main.tf",
    ]
    for name in expected:
        assert name in run.files


def test_the_numbers_match_the_sample_estate(run):
    summary = run.report["summary"]
    assert summary["resources_checked"] == 15
    assert summary["findings"] == 13
    assert summary["by_severity"] == {"high": 4, "medium": 5, "low": 4}
    assert summary["by_category"] == {"risk": 8, "cost": 5}
    assert summary["savings"]["total_usd"] == 43.65
    assert summary["savings"]["includes_upper_bounds"] is True
    assert summary["savings"]["estimated"] == 5
    assert summary["fixes"] == {
        "proposed": 3, "blocked": 1, "needs a person": 4, "not yet supported": 5,
    }


def test_coverage_names_what_could_not_be_checked(run):
    coverage = run.report["coverage"]
    assert coverage["fully_checked"] == 13
    assert [p["name"] for p in coverage["partly_checked"]] == ["legacy-sg"]
    assert coverage["no_rules_for_type"] == {"vpc": 1}


def test_terraform_gaps_are_reported(run):
    assert len(run.gaps) == 7
    assert any("missing ami" in gap for gap in run.gaps)
    assert any("'vpc' is not supported yet" in gap for gap in run.gaps)
    assert len(read(run, "terraform/GAPS.txt").splitlines()) == 7


def test_shared_is_applied_first_and_billing_after_it(run):
    lines = [l for l in read(run, "terraform/current/APPLY_ORDER.md").splitlines()
             if l[:2] in ("1.", "2.", "3.")]
    assert lines[0].startswith("1. `shared`")
    assert "Needs: shared" in [l for l in lines if "`billing`" in l][0]


def test_current_code_is_untouched_and_proposed_code_has_the_fixes(run):
    current = read(run, "terraform/current/shared/main.tf")
    proposed = read(run, "terraform/proposed/shared/main.tf")
    assert "admin_cidr" not in current
    assert "cidr_blocks = [var.admin_cidr]" in proposed
    assert 'variable "admin_cidr"' in proposed
    assert 'cidr_blocks = ["0.0.0.0/0"]' in proposed  # the HTTPS rule stays open


def test_billing_looks_up_the_shared_group_and_gets_the_server_fix(run):
    proposed = read(run, "terraform/proposed/billing/main.tf")
    assert 'data "aws_security_group" "admin_access"' in proposed
    assert 'id = "sg-0a1b2c3d4e5f00001"' in proposed
    assert "metadata_options {" in proposed


def test_the_diff_covers_the_three_changed_folders_only(run):
    diff = read(run, "terraform/fixes.diff")
    for layer in ("shared", "billing", "website"):
        assert f"+++ proposed/{layer}/main.tf" in diff
    assert "APPLY_ORDER" not in diff
    assert "public_access_block" in diff


def test_the_markdown_report_shows_fix_status_and_gaps(run):
    text = read(run, "report.md")
    assert "- Terraform fix: proposed." in text
    assert "- Terraform fix: needs a person." in text
    assert "## Terraform: what could not be generated" in text
    assert "Terraform fixes: proposed 3, blocked 1, needs a person 4, not yet supported 5" in text


def test_the_json_report_is_valid_json(run):
    assert json.loads(read(run, "report.json"))["summary"]["findings"] == 13


def test_default_explanations_are_the_written_text(run):
    assert {f["explained_by"] for f in run.report["findings"]} == {"fixed text"}


def test_running_again_replaces_old_terraform(tmp_path):
    out = tmp_path / "demo"
    run_pipeline(SAMPLE, out)
    stray = out / "terraform" / "current" / "old-layer" / "main.tf"
    stray.parent.mkdir(parents=True)
    stray.write_text("old", encoding="utf-8")
    run_pipeline(SAMPLE, out)
    assert not stray.exists()