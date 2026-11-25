import json
import logging

from pydantic import BaseModel, Field, field_validator

from app.findings import Finding
from app.llm_core import ask_structured
from app.reporting.knowledge import KNOWLEDGE

logger = logging.getLogger(__name__)

SYSTEM = (
    "You rewrite short explanations of cloud configuration findings for a non-expert manager. "
    "Use ONLY the facts provided. Do not add numbers, prices, service names or claims that are "
    "not in the facts. Reply with JSON only."
)


class Explanation(BaseModel):
    summary: str = Field(min_length=1, max_length=300)
    why_it_matters: str = Field(min_length=1, max_length=400)
    suggested_fix: str = Field(min_length=1, max_length=400)

    @field_validator("summary", "why_it_matters", "suggested_fix")
    @classmethod
    def no_money(cls, value: str) -> str:
        if "$" in value:
            raise ValueError("explanations must not contain dollar amounts")
        return value


def llm_explanation(finding: Finding, resource: dict, backend=None):
    """An Explanation from the model, or None if it cannot give a valid one."""
    facts = {
        "finding": finding.title,
        "severity": finding.severity,
        "resource_type": resource.get("resource_type"),
        "evidence": finding.detail,
        "reference_reason": KNOWLEDGE[finding.rule_id]["why"],
        "reference_fix": KNOWLEDGE[finding.rule_id]["fix"],
    }
    try:
        return ask_structured(SYSTEM, json.dumps(facts), Explanation, backend=backend)
    except Exception:  # invalid output, model down, anything
        logger.warning("no LLM explanation for rule %s on resource %s", finding.rule_id, finding.resource_id)
        return None


def llm_explainer(finding: Finding, resource: dict):
    return llm_explanation(finding, resource)