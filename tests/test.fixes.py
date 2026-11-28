import pytest

from app.findings import RULES
from app.findings.rules import is_world_admin_rule
from app.generation import generate_layers, generate_terraform, unified_diff
from app.generation.templates import needs_admin_cidr
from app.reporting.fixes import RULE_FIX, fix_status


def rule(low, high=None, cidr="0.0.0.0/0", protocol="tcp"):
    return {"protocol": protocol, "from_port": low,
            "to_port": high if high is not None else low, "cidr": cidr}


def group(rid=1, inbound=None, app="shared", name="admin-access"):
    return {"id": rid, "resource_type": "security_group", "resource_id": f"sg-{rid}",
            "name": name, "app": app, "config": {"inbound": inbound or []}}


def bucket(config, rid=1, app="shared"):
    return {"id": rid, "resource_type": "s3_bucket", "resource_id": f"bucket-{rid}",
            "name": f"bucket-{rid}", "app": app, "config": config}


def server(tokens):
    return {"id": 1, "resource_type": "ec2_instance", "resource_id": "i-1", "name": "web",
            "app": "shared",
            "config": {"ami": "ami-0123456789abcdef0", "instance_type": "t3.small",
                       "metadata_http_tokens": tokens}}


@pytest.mark.parametrize(
    "perm, expected",
    [
        (rule(22), True), (rule(3389), True), (rule(0, 65535), True), (rule(22, cidr="::/0"), True),
        (rule(443), False), (rule(22, cidr="203.0.113.0/24"), False), (rule(22, protocol="udp"), False),
        ({"cidr": "0.0.0.0/0", "protocol": "tcp"}, False), ("oops", False), (None, False),
    ],
)
def test_is_world_admin_rule(perm, expected):
    assert is_world_admin_rule(perm) is expected


@pytest.mark.parametrize(
    "resource",
    [
        {"resource_type": "s3_bucket", "config": {}},
        {"resource_type": "security_group", "config": {"inbound": "oops"}},
        {"resource_type": "security_group", "config": None},
        {"resource_type": "security_group", "config": {"inbound": [rule(443)]}},
    ],
)
def test_needs_admin_cidr_is_false_for_everything_else(resource):
    assert needs_admin_cidr(resource) is False


# security groups
def test_fix_restricts_only_the_open_admin_rule():
    text = generate_terraform(
        "us-east-1", [group(inbound=[rule(22), rule(443), rule(5432)])], [], fix=True
    ).main_tf
    assert text.count("cidr_blocks = [var.admin_cidr]") == 1
    assert text.count('cidr_blocks = ["0.0.0.0/0"]') == 2  # HTTPS and the database port stay
    assert "# Proposed fix" in text


def test_the_variable_is_declared_and_validated():
    text = generate_terraform("us-east-1", [group(inbound=[rule(22)])], [], fix=True).main_tf
    assert 'variable "admin_cidr"' in text
    assert "can(cidrhost(var.admin_cidr, 0))" in text
    assert '!= "0.0.0.0/0"' in text


def test_without_fix_the_output_is_unchanged():
    text = generate_terraform("us-east-1", [group(inbound=[rule(22)])], []).main_tf
    assert "admin_cidr" not in text
    assert 'cidr_blocks = ["0.0.0.0/0"]' in text


def test_the_variable_appears_only_in_folders_that_need_it():
    resources = [
        group(1, [rule(22)], app="shared", name="admin-access"),
        group(2, [rule(443)], app="billing", name="billing-web"),
    ]
    files = generate_layers("us-east-1", resources, [], fix=True).files
    assert 'variable "admin_cidr"' in files["shared/main.tf"]
    assert 'variable "admin_cidr"' not in files["billing/main.tf"]


# buckets
@pytest.mark.parametrize(
    "config, expected",
    [({"public_access_block": False}, True), ({"public_access_block": True}, False), ({}, False)],
)
def test_bucket_fix_only_when_the_block_is_known_to_be_missing(config, expected):
    text = generate_terraform("us-east-1", [bucket(config)], [], fix=True).main_tf
    assert ('resource "aws_s3_bucket_public_access_block"' in text) is expected


def test_bucket_fix_blocks_everything_and_is_off_by_default():
    config = {"public_access_block": False}
    fixed = generate_terraform("us-east-1", [bucket(config)], [], fix=True).main_tf
    for setting in ("block_public_acls", "block_public_policy",
                    "ignore_public_acls", "restrict_public_buckets"):
        assert f"{setting}       = true" in fixed or f"{setting}     = true" in fixed \
            or f"{setting} " in fixed
    assert "public_access_block" not in generate_terraform("us-east-1", [bucket(config)], []).main_tf


# servers
def test_server_fix_requires_imdsv2():
    text = generate_terraform("us-east-1", [server("optional")], [], fix=True).main_tf
    assert "metadata_options {" in text
    assert 'http_tokens = "required"' in text


@pytest.mark.parametrize("tokens", ["required", None])
def test_no_server_fix_when_already_required_or_unknown(tokens):
    text = generate_terraform("us-east-1", [server(tokens)], [], fix=True).main_tf
    assert "metadata_options" not in text


# diff, ids, decisions
def test_diff_shows_changed_files_only():
    current = {"a/main.tf": "one\ntwo\n", "b/main.tf": "same\n"}
    proposed = {"a/main.tf": "one\nTWO\n", "b/main.tf": "same\n"}
    diff = unified_diff(current, proposed)
    assert "--- current/a/main.tf" in diff
    assert "+++ proposed/a/main.tf" in diff
    assert "-two" in diff and "+TWO" in diff
    assert "b/main.tf" not in diff


def test_identical_files_give_an_empty_diff():
    assert unified_diff({"a": "x\n"}, {"a": "x\n"}) == ""


def test_generation_reports_which_resources_were_written():
    nameless = {**group(2), "name": None}
    result = generate_layers("us-east-1", [group(1), nameless], [])
    assert result.generated_ids == {1}


def test_every_rule_has_a_fix_decision():
    assert set(RULE_FIX) == set(RULES)
    for kind, note in RULE_FIX.values():
        assert kind in ("auto", "person", "later")
        assert note


def test_fix_status_values():
    assert fix_status("ec2-imdsv1", 5, {5})["status"] == "proposed"
    assert fix_status("ec2-imdsv1", 5, set())["status"] == "blocked"
    assert fix_status("sg-db-ports-open", 5, {5})["status"] == "needs a person"
    assert fix_status("rds-public", 5, {5})["status"] == "not yet supported"