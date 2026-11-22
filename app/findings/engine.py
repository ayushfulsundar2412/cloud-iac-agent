import logging #Used to write a warning if rule goes wrong
from dataclasses import dataclass

logger = logging.getLogger(__name__)

SEVERITIES = ("high", "medium", "low")
CATEGORIES = ("risk", "cost")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)} # To sort severities like 0:high, 1:medium, 2:low


@dataclass(frozen=True) # Means it cant be changed once its created : Frozen=True
class Finding:
    rule_id: str #Which rule fired, like sg-admin-open
    severity: str
    category: str
    resource_id: int  # our database id for the resource not aws id
    title: str  #A short sentence about the problem
    detail: dict      # the evidence


RULES: dict[str, dict] = {}


def rule(rule_id: str, severity: str, category: str, applies_to: tuple, title: str):
    """Register a check.

    The check receives a resource's config dictionary. It returns a dictionary
    of evidence if the problem is present, or None if all is well or unknown.
    """
    #Checks for any typo and not in severity or category like "hihg"
    if severity not in SEVERITIES:
        raise ValueError(f"Unknown severity: {severity!r}")
    if category not in CATEGORIES:
        raise ValueError(f"Unknown category: {category!r}") 

    def register(check):
        if rule_id in RULES:
            raise ValueError(f"Duplicate rule id: {rule_id}")
        RULES[rule_id] = {
            "severity": severity,
            "category": category,
            "applies_to": tuple(applies_to),
            "title": title,
            "check": check,
        }
        return check

    return register


def evaluate(resources: list[dict]) -> list[Finding]:
    """Run every matching rule on every resource, and return sorted findings."""
    findings = []
    # It goes through rows from your database and starts with empty report for each resource then checks through settings.
    for resource in resources:
        config = resource.get("config") or {}
        for rule_id, meta in RULES.items():
            if resource["resource_type"] not in meta["applies_to"]:
                continue
            try:
                detail = meta["check"](config)
            except Exception:  # one odd resource must not stop the whole scan
                logger.warning("rule %s failed on resource %s", rule_id, resource["id"])
                continue
            if detail is not None:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=meta["severity"],
                        category=meta["category"],
                        resource_id=resource["id"],
                        title=meta["title"],
                        detail=detail,
                    )
                )
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.rule_id, f.resource_id))
    return findings