from dataclasses import dataclass

AS_OF = "2026-11-23"
PRICED_REGION = "us-east-1"
HOURS_PER_MONTH = 730  # our assumption: 24 hours x 365 days / 12 months

EBS_GP_PAGE = "https://aws.amazon.com/ebs/general-purpose/"
EBS_PRICING_PAGE = "https://aws.amazon.com/ebs/pricing/"
IPV4_BLOG = "https://aws.amazon.com/blogs/aws/new-aws-public-ipv4-address-charge-public-ip-insights"


@dataclass(frozen=True)
class Price:
    usd: float
    unit: str
    source: str


PRICES = {
    "ebs-gp2": Price(0.10, "per GB-month", EBS_GP_PAGE),
    "ebs-gp3": Price(0.08, "per GB-month", EBS_GP_PAGE),
    "ebs-snapshot": Price(0.05, "per GB-month", EBS_PRICING_PAGE),
    "public-ipv4": Price(0.005, "per IP-hour", IPV4_BLOG),
}


@dataclass(frozen=True)
class Estimate:
    monthly_usd: float
    kind: str          # always "estimated": we never claim an actual bill figure
    method: str        # the arithmetic, so anyone can check it
    source: str        # the page the price came from
    as_of: str         # when the price was checked
    upper_bound: bool = False


def _size(config: dict):
    size = config.get("size_gb")
    if type(size) in (int, float) and size > 0:  # True is not a size
        return size
    return None


def _ebs_unattached(config: dict):
    size = _size(config)
    price = {"gp2": PRICES["ebs-gp2"], "gp3": PRICES["ebs-gp3"]}.get(config.get("volume_type"))
    if size is None or price is None:
        return None
    return Estimate(
        monthly_usd=round(size * price.usd, 2),
        kind="estimated",
        method=f"{size:g} GB x ${price.usd:.2f} per GB-month ({config['volume_type']}): what the unused disk costs to keep",
        source=price.source,
        as_of=AS_OF,
    )


def _ebs_gp2(config: dict):
    size = _size(config)
    if size is None:
        return None
    gp2, gp3 = PRICES["ebs-gp2"], PRICES["ebs-gp3"]
    return Estimate(
        monthly_usd=round(size * (gp2.usd - gp3.usd), 2),
        kind="estimated",
        method=(
            f"{size:g} GB x (${gp2.usd:.2f} - ${gp3.usd:.2f}) per GB-month. "
            "Assumes the disk does not need more than gp3's free baseline of 3,000 IOPS and 125 MB/s"
        ),
        source=gp2.source,
        as_of=AS_OF,
    )


def _snapshot_old(config: dict):
    size = _size(config)
    if size is None:
        return None
    price = PRICES["ebs-snapshot"]
    return Estimate(
        monthly_usd=round(size * price.usd, 2),
        kind="estimated",
        method=(
            f"Up to {size:g} GB x ${price.usd:.2f} per GB-month. "
            "Snapshots are stored incrementally, so the billed size is usually smaller"
        ),
        source=price.source,
        as_of=AS_OF,
        upper_bound=True,
    )


def _eip_unassociated(config: dict):
    price = PRICES["public-ipv4"]
    return Estimate(
        monthly_usd=round(HOURS_PER_MONTH * price.usd, 2),
        kind="estimated",
        method=f"{HOURS_PER_MONTH} hours x ${price.usd:.3f} per IP-hour",
        source=price.source,
        as_of=AS_OF,
    )


ESTIMATORS = {
    "ebs-unattached": _ebs_unattached,
    "ebs-gp2": _ebs_gp2,
    "snapshot-old": _snapshot_old,
    "eip-unassociated": _eip_unassociated,
}


def estimate_savings(rule_id: str, config: dict, region: str):
    """An Estimate, or None when we cannot honestly give one."""
    if region != PRICED_REGION:
        return None
    estimator = ESTIMATORS.get(rule_id)
    if estimator is None:
        return None
    try:
        return estimator(config)
    except Exception:  # odd data means no estimate, never a crash
        return None