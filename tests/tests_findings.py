import pytest

from app.findings import RULES, evaluate
from app.findings.engine import rule


def resource(rtype, config, rid=1):
    return {"id": rid, "resource_type": rtype, "config": config}


def fired(rtype, config):
    return [f.rule_id for f in evaluate([resource(rtype, config)])]


def inbound(low, high, cidr="0.0.0.0/0", protocol="tcp"):
    return {"inbound": [{"protocol": protocol, "from_port": low, "to_port": high, "cidr": cidr}]}


# security groups
def test_ssh_open_to_the_world_is_flagged():
    assert fired("security_group", inbound(22, 22)) == ["sg-admin-open"]


def test_https_open_to_the_world_is_fine():
    assert fired("security_group", inbound(443, 443)) == []


def test_ssh_from_a_private_range_is_fine():
    assert fired("security_group", inbound(22, 22, cidr="203.0.113.0/24")) == []


def test_ipv6_world_range_is_flagged():
    assert fired("security_group", inbound(22, 22, cidr="::/0")) == ["sg-admin-open"]


def test_database_port_open_to_the_world_is_flagged():
    assert fired("security_group", inbound(5432, 5432)) == ["sg-db-ports-open"]


def test_a_full_port_range_flags_both_admin_and_database():
    assert fired("security_group", inbound(0, 65535)) == ["sg-admin-open", "sg-db-ports-open"]


def test_all_traffic_from_anywhere_is_flagged_once():
    config = {"inbound": [{"protocol": "-1", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"}]}
    assert fired("security_group", config) == ["sg-all-traffic-open"]


def test_a_rule_without_ports_is_not_a_finding():
    config = {"inbound": [{"protocol": "tcp", "cidr": "0.0.0.0/0"}]}
    assert fired("security_group", config) == []


def test_evidence_names_the_exposed_service():
    finding = evaluate([resource("security_group", inbound(22, 22))])[0]
    assert finding.detail["rules"][0]["services"] == ["SSH"]
    assert finding.detail["rules"][0]["ports"] == "22-22"


# one table for the simple rules: (type, config, expected rule or None)
CASES = [
    ("s3_bucket", {"public_access_block": False}, "s3-no-public-access-block"),
    ("s3_bucket", {"public_access_block": True}, None),
    ("rds_instance", {"publicly_accessible": True}, "rds-public"),
    ("rds_instance", {"backup_retention_days": 0}, "rds-no-backups"),
    ("rds_instance", {"backup_retention_days": 7}, None),
    ("rds_instance", {"storage_encrypted": False}, "rds-unencrypted"),
    ("ec2_instance", {"metadata_http_tokens": "optional"}, "ec2-imdsv1"),
    ("ec2_instance", {"metadata_http_tokens": "required"}, None),
    ("ebs_volume", {"state": "available"}, "ebs-unattached"),
    ("ebs_volume", {"state": "in-use"}, None),
    ("ebs_volume", {"volume_type": "gp2"}, "ebs-gp2"),
    ("ebs_volume", {"volume_type": "gp3"}, None),
    ("ebs_snapshot", {"age_days": 400}, "snapshot-old"),
    ("ebs_snapshot", {"age_days": 10}, None),
    ("elastic_ip", {"associated": False}, "eip-unassociated"),
    ("elastic_ip", {"associated": True}, None),
]


@pytest.mark.parametrize("rtype, config, expected", CASES)
def test_simple_rules(rtype, config, expected):
    assert fired(rtype, config) == ([expected] if expected else [])


@pytest.mark.parametrize(
    "rtype",
    ["security_group", "s3_bucket", "rds_instance", "ec2_instance",
     "ebs_volume", "ebs_snapshot", "elastic_ip"],
)
def test_missing_data_is_never_a_finding(rtype):
    assert fired(rtype, {}) == []


def test_snapshot_age_limit_is_exclusive():
    assert fired("ebs_snapshot", {"age_days": 90}) == []
    assert fired("ebs_snapshot", {"age_days": 91}) == ["snapshot-old"]


def test_false_is_not_zero_days_of_backups():
    assert fired("rds_instance", {"backup_retention_days": False}) == []


def test_rules_only_apply_to_their_own_resource_type():
    assert fired("s3_bucket", {"state": "available", "publicly_accessible": True}) == []


def test_malformed_data_does_not_crash_the_scan():
    assert fired("security_group", {"inbound": "oops"}) == []
    assert evaluate([{"id": 1, "resource_type": "security_group", "config": "nonsense"}]) == []


def test_findings_are_sorted_by_severity():
    resources = [
        resource("ebs_volume", {"volume_type": "gp2"}, rid=1),
        resource("security_group", inbound(22, 22), rid=2),
        resource("rds_instance", {"backup_retention_days": 0}, rid=3),
    ]
    assert [f.rule_id for f in evaluate(resources)] == [
        "sg-admin-open", "rds-no-backups", "ebs-gp2",
    ]


# the registry itself
def test_duplicate_rule_ids_are_rejected():
    with pytest.raises(ValueError):
        rule("sg-admin-open", "high", "risk", ("security_group",), "again")(lambda config: None)


def test_unknown_severity_is_rejected():
    with pytest.raises(ValueError):
        rule("temporary", "urgent", "risk", ("security_group",), "bad")


def test_every_rule_is_well_formed():
    assert len(RULES) >= 12
    for rule_id, meta in RULES.items():
        assert meta["severity"] in ("high", "medium", "low"), rule_id
        assert meta["category"] in ("risk", "cost"), rule_id
        assert meta["applies_to"], rule_id
        assert meta["title"], rule_id