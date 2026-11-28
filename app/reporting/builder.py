import re
from dataclasses import asdict

from app.findings import Finding, evaluate
from app.reporting.knowledge import KNOWLEDGE
from app.reporting.pricing import estimate_savings
from app.reporting.fixes import fix_status

SEVERITIES = ("high", "medium", "low")
CATEGORIES = ("risk", "cost")

# the settings each resource type's rules read, used to say what could not be checked
ASSESSED_KEYS = {
    "security_group": ("inbound",),
    "s3_bucket": ("public_access_block",),
    "rds_instance": ("publicly_accessible", "backup_retention_days", "storage_encrypted"),
    "ec2_instance": ("metadata_http_tokens",),
    "ebs_volume": ("state", "volume_type"),
    "ebs_snapshot": ("age_days",),
    "elastic_ip": ("associated",),
}


def describe_evidence(finding: Finding) -> str:
    detail = finding.detail
    if "rules" in detail:
        return "; ".join(
            f"{' and '.join(hit['services'])} (ports {hit['ports']}) open to {hit['source']}"
            for hit in detail["rules"]
        )
    if "sources" in detail:
        return "all traffic allowed from " + ", ".join(detail["sources"])
    return ", ".join(f"{key} = {value}" for key, value in detail.items())


def _coverage(resources: list[dict]) -> dict:
    partly, unsupported, with_rules = [], {}, 0
    for r in resources:
        keys = ASSESSED_KEYS.get(r["resource_type"])
        if keys is None:
            unsupported[r["resource_type"]] = unsupported.get(r["resource_type"], 0) + 1
            continue
        with_rules += 1
        config = r.get("config") if isinstance(r.get("config"), dict) else {}
        missing = [key for key in keys if config.get(key) is None]
        if missing:
            partly.append(
                {"id": r["id"], "name": r.get("name"), "type": r["resource_type"], "missing": missing}
            )
    return {
        "fully_checked": with_rules - len(partly),
        "partly_checked": partly,
        "no_rules_for_type": unsupported,
    }


def _savings(items: list[dict]) -> dict:
    cost_items = [i for i in items if i["category"] == "cost"]
    best = {}  # resource id -> its largest estimate, so savings are never counted twice
    for item in cost_items:
        estimate = item["estimate"]
        if estimate is None:
            continue
        rid = item["resource"]["id"]
        if rid not in best or estimate["monthly_usd"] > best[rid]["estimate"]["monthly_usd"]:
            best[rid] = item
    rows = sorted(best.values(), key=lambda i: (-i["estimate"]["monthly_usd"], i["resource"]["id"]))
    return {
        "total_usd": round(sum(i["estimate"]["monthly_usd"] for i in rows), 2),
        "includes_upper_bounds": any(i["estimate"]["upper_bound"] for i in rows),
        "cost_findings": len(cost_items),
        "estimated": sum(1 for i in cost_items if i["estimate"] is not None),
        "rows": [
            {
                "resource": i["resource"]["name"] or i["resource"]["aws_id"] or i["resource"]["id"],
                "rule_id": i["rule_id"],
                "title": i["title"],
                "monthly_usd": i["estimate"]["monthly_usd"],
                "upper_bound": i["estimate"]["upper_bound"],
            }
            for i in rows
        ],
    }

def build_report(
    scan: dict,
    resources: list[dict],
    explainer=None,
    generated_at: str = "",
    generated_ids=None,
    terraform_gaps=None,
) -> dict:
    by_id = {r["id"]: r for r in resources}
    items = []
    for finding in evaluate(resources):
        resource = by_id[finding.resource_id]
        config = resource.get("config") if isinstance(resource.get("config"), dict) else {}

        estimate = None
        if finding.category == "cost":
            found = estimate_savings(finding.rule_id, config, scan["region"])
            estimate = asdict(found) if found else None

        explanation = None
        if explainer is not None:
            try:
                explanation = explainer(finding, resource)
            except Exception:  # the report must never fail because of the model
                explanation = None

        knowledge = KNOWLEDGE[finding.rule_id]
        terraform_fix = (
            fix_status(finding.rule_id, finding.resource_id, generated_ids)
            if generated_ids is not None
            else None
        )
        items.append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "resource": {
                    "id": resource["id"],
                    "aws_id": resource.get("resource_id"),
                    "type": resource["resource_type"],
                    "name": resource.get("name"),
                    "app": resource.get("app"),
                },
                "evidence": describe_evidence(finding),
                "summary": explanation.summary if explanation else None,
                "why_it_matters": explanation.why_it_matters if explanation else knowledge["why"],
                "suggested_fix": explanation.suggested_fix if explanation else knowledge["fix"],
                "explained_by": "llm" if explanation else "fixed text",
                "estimate": estimate,
                "terraform_fix": terraform_fix,
            }
        )

    # counted once, after the loop, so an empty estate works too
    fixes = None
    if generated_ids is not None:
        fixes = {}
        for item in items:
            status = item["terraform_fix"]["status"]
            fixes[status] = fixes.get(status, 0) + 1

    return {
        "scan": {"id": scan["id"], "account_id": scan["account_id"], "region": scan["region"]},
        "generated_at": generated_at,
        "summary": {
            "resources_checked": len(resources),
            "findings": len(items),
            "by_severity": {s: sum(1 for i in items if i["severity"] == s) for s in SEVERITIES},
            "by_category": {c: sum(1 for i in items if i["category"] == c) for c in CATEGORIES},
            "savings": _savings(items),
            "fixes": fixes,
        },
        "findings": items,
        "coverage": _coverage(resources),
        "terraform": {"gaps": list(terraform_gaps)} if terraform_gaps is not None else None,
    }
# ---- markdown ----

def _money(value: float) -> str:
    return f"${value:,.2f}"


def _code(value) -> str:
    """Untrusted text goes inside a code span, where it cannot become a link or markup."""
    return "`" + str(value).replace("`", "'").replace("\n", " ") + "`"


def _plain(value) -> str:
    """Strip link and tag characters from text that came from outside our fixed strings."""
    return " ".join(re.sub(r"[<>\[\]`]", "", str(value)).split())


def _block(number: int, item: dict) -> list[str]:
    res = item["resource"]
    label = res["name"] or res["aws_id"] or res["id"]
    lines = [
        f"### {number}. {_plain(item['title'])} ({item['severity']})",
        "",
        f"- Resource: {_code(label)} | type {_code(res['type'])} | ID {_code(res['aws_id'] or 'unknown')}",
        f"- Evidence: {_code(item['evidence'])}",
    ]
    if item["summary"]:
        lines.append(f"- In plain words: {_plain(item['summary'])}")
    lines += [
        f"- Why it matters: {_plain(item['why_it_matters'])}",
        f"- Suggested fix: {_plain(item['suggested_fix'])}",
    ]
    if item.get("terraform_fix"):
        fix = item["terraform_fix"]
        lines.append(f"- Terraform fix: {fix['status']}. {_plain(fix['note'])}")
    if item["category"] == "cost":
        estimate = item["estimate"]
        if estimate:
            prefix = "up to " if estimate["upper_bound"] else ""
            lines.append(
                f"- Estimated saving: {prefix}{_money(estimate['monthly_usd'])} per month. "
                f"Method: {_plain(estimate['method'])}. "
                f"Source: {estimate['source']} (prices as of {estimate['as_of']})"
            )
        else:
            lines.append(
                "- Estimated saving: not estimated (the size or type is missing, "
                "or there is no price for this region)"
            )
    lines.append("")
    return lines


def render_markdown(report: dict) -> str:
    scan, summary = report["scan"], report["summary"]
    savings, sev, cat = summary["savings"], summary["by_severity"], summary["by_category"]
    lines = [
        "# Cloud estate report",
        "",
        f"Scan {scan['id']} | account {_code(scan['account_id'])} | region {_code(scan['region'])} "
        f"| generated {_plain(report['generated_at'] or 'not recorded')}",
        "",
        "## Summary",
        "",
        f"- Resources checked: {summary['resources_checked']}",
        f"- Findings: {summary['findings']} (high {sev['high']}, medium {sev['medium']}, low {sev['low']})",
        f"- Risk findings: {cat['risk']}. Cost findings: {cat['cost']}.",
    ]
    if savings["cost_findings"] == 0:
        lines.append("- Potential savings: no cost findings")
    elif savings["estimated"] == 0:
        lines.append("- Potential savings: not estimated (no cost finding had the data and a known price)")
    else:
        prefix = "up to " if savings["includes_upper_bounds"] else ""
        lines.append(
            f"- Potential savings (estimated): {prefix}{_money(savings['total_usd'])} per month, "
            f"from {savings['estimated']} of {savings['cost_findings']} cost findings"
        )
    if summary.get("fixes"):
        order = ("proposed", "blocked", "needs a person", "not yet supported")
        counts = ", ".join(
            f"{status} {summary['fixes'][status]}" for status in order if status in summary["fixes"]
        )
        lines.append(f"- Terraform fixes: {counts}")
    lines += [
        "",
        "Findings are potential, not promises. A person should review each item before acting on it.",
        "",
    ]

    for category, heading in (("risk", "Risk findings"), ("cost", "Cost findings")):
        group = [i for i in report["findings"] if i["category"] == category]
        lines += [f"## {heading}", ""]
        if not group:
            lines += ["None found.", ""]
        for number, item in enumerate(group, start=1):
            lines += _block(number, item)

    if savings["rows"]:
        lines += [
            "## Savings estimate by resource",
            "",
            "| Resource | Finding | Estimated monthly saving |",
            "| --- | --- | --- |",
        ]
        for row in savings["rows"]:
            prefix = "up to " if row["upper_bound"] else ""
            lines.append(
                f"| {_code(row['resource'])} | {_plain(row['title'])} | {prefix}{_money(row['monthly_usd'])} |"
            )
        lines += [
            "",
            "Where one resource has several cost findings, only the largest is counted, "
            "so a saving is never added twice.",
            "",
        ]

    terraform = report.get("terraform")
    if terraform:
        lines += ["## Terraform: what could not be generated", ""]
        if terraform["gaps"]:
            lines += [f"- {_plain(gap)}" for gap in terraform["gaps"]]
        else:
            lines.append("None.")
        lines.append("")

    cov = report["coverage"]
    lines += ["## What this report could not check", "", f"- Fully checked: {cov['fully_checked']} resources"]
    if cov["partly_checked"]:
        lines.append(
            f"- Partly checked, because some settings were missing: {len(cov['partly_checked'])} resources"
        )
        for part in cov["partly_checked"]:
            lines.append(
                f"  - {_code(part['name'] or part['id'])} ({_plain(part['type'])}) "
                f"is missing {', '.join(part['missing'])}"
            )
    if cov["no_rules_for_type"]:
        kinds = ", ".join(f"{_plain(k)} ({n})" for k, n in sorted(cov["no_rules_for_type"].items()))
        lines.append(f"- No rules yet for these types: {kinds}")

    lines += [
        "",
        "## How to read this report",
        "",
        "- Every finding comes from a fixed rule that fires only when a setting is explicitly the risky value. "
        "A missing setting is never counted as a problem. It is listed above instead.",
        "- Dollar figures are estimates from published list prices for one region. Each shows its method, "
        "source and date. They are not taken from a bill.",
        "- Figures marked \"up to\" are upper bounds.",
        "- Explanations are written in advance, unless the report says a language model wrote them. "
        "Model text is checked for shape and cannot contain prices.",
        "- Terraform fixes are proposals, shown as a diff against the current code. A person must review "
        "and apply them, and some change who can reach a system.",
    ]
    return "\n".join(lines) + "\n"