import pytest

from app.reporting.pricing import PRICES, estimate_savings


def est(rule_id, config, region="us-east-1"):
    return estimate_savings(rule_id, config, region)


@pytest.mark.parametrize(
    "volume_type, expected", [("gp3", 8.0), ("gp2", 10.0)]
)
def test_unattached_disk_costs_its_full_price(volume_type, expected):
    result = est("ebs-unattached", {"size_gb": 100, "volume_type": volume_type})
    assert result.monthly_usd == expected


def test_gp2_to_gp3_saves_the_price_difference():
    assert est("ebs-gp2", {"size_gb": 500}).monthly_usd == 10.0


def test_old_snapshot_estimate_is_an_upper_bound():
    result = est("snapshot-old", {"size_gb": 200})
    assert result.monthly_usd == 10.0
    assert result.upper_bound is True


def test_idle_public_ip_costs_a_month_of_hours():
    assert est("eip-unassociated", {}).monthly_usd == 3.65


def test_every_estimate_carries_its_method_source_and_date():
    result = est("ebs-unattached", {"size_gb": 100, "volume_type": "gp3"})
    assert result.kind == "estimated"
    assert "100 GB" in result.method
    assert result.source.startswith("https://aws.amazon.com/")
    assert result.as_of


def test_other_regions_are_not_estimated():
    assert est("ebs-unattached", {"size_gb": 100, "volume_type": "gp3"}, "eu-west-1") is None


@pytest.mark.parametrize(
    "rule_id, config",
    [
        ("ebs-unattached", {"volume_type": "gp2"}),                      # no size
        ("ebs-unattached", {"size_gb": 100, "volume_type": "io1"}),      # no price for this type
        ("ebs-unattached", {"size_gb": "big", "volume_type": "gp2"}),    # not a number
        ("ebs-unattached", {"size_gb": -5, "volume_type": "gp2"}),       # negative
        ("ebs-unattached", {"size_gb": True, "volume_type": "gp2"}),     # True is not a size
        ("ebs-unattached", {"size_gb": 100, "volume_type": ["gp2"]}),    # unreadable type
        ("ebs-gp2", {}),
        ("snapshot-old", {"size_gb": 0}),
        ("sg-admin-open", {"size_gb": 100}),                             # risk rules have no price
    ],
)
def test_no_estimate_when_data_or_price_is_missing(rule_id, config):
    assert est(rule_id, config) is None


def test_the_price_table_is_complete_and_sourced():
    assert set(PRICES) == {"ebs-gp2", "ebs-gp3", "ebs-snapshot", "public-ipv4"}
    for price in PRICES.values():
        assert price.usd > 0
        assert price.source.startswith("https://")