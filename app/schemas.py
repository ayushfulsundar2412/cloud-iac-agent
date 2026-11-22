from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    """What the client sends to start a scan."""
    account_id: str = Field(pattern=r"^\d{12}$")  # AWS account IDs are 12 digits or else rejected
    region: str


class ScanOut(BaseModel):
    """What we send back."""
    id: int
    account_id: str
    region: str
    status: str
    started_at: datetime


class ResourceCreate(BaseModel):
    resource_type: str
    resource_id: str
    name: str | None = None
    app: str = Field(default="shared", min_length=1, max_length=50, pattern=r"^[a-z0-9-]+$")
    config: dict[str, Any] = Field(default_factory=dict)
    monthly_cost_usd: float | None = Field(default=None, ge=0) #Money can be float for now but for real cost estimates we would use decimal


class ResourceOut(ResourceCreate):
    id: int
    scan_id: int
    created_at: datetime

class DependencyCreate(BaseModel):
    from_resource_id: int
    to_resource_id: int
    relationship: str = Field(min_length=1)


class DependencyOut(DependencyCreate):
    id: int
    scan_id: int

class FindingOut(BaseModel):
    id: int
    scan_id: int
    resource_id: int
    resource_name: str | None
    resource_type: str
    rule_id: str
    severity: Literal["high", "medium", "low"]
    category: Literal["risk", "cost"]
    title: str
    detail: dict[str, Any]
    created_at: datetime


class AnalysisSummary(BaseModel):
    scan_id: int
    resources_checked: int
    findings: int
    by_severity: dict[str, int]
    by_category: dict[str, int]