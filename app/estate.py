import json
import re
from pathlib import Path

MAX_FILE_BYTES = 1_000_000

KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
APP_PATTERN = re.compile(r"^[a-z0-9-]{1,50}$")
ACCOUNT_PATTERN = re.compile(r"^\d{12}$")
REGION_PATTERN = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")


class EstateError(ValueError):
    """The estate file is not valid."""


def _fail(message: str):
    raise EstateError(message)


def load_estate(path) -> dict:
    """Read and validate an estate file."""
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        _fail("the estate file is too large")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EstateError(f"not valid JSON: {exc.msg} at line {exc.lineno}") from exc
    return parse_estate(data)


def parse_estate(data) -> dict:
    """Check the shape of an estate and turn resource keys into numeric ids."""
    if not isinstance(data, dict):
        _fail("the file must contain a JSON object")

    scan = data.get("scan")
    if not isinstance(scan, dict):
        _fail("'scan' must be an object")
    account, region = scan.get("account_id"), scan.get("region")
    if not (isinstance(account, str) and ACCOUNT_PATTERN.match(account)):
        _fail("scan.account_id must be exactly 12 digits")
    if not (isinstance(region, str) and REGION_PATTERN.match(region)):
        _fail("scan.region must look like us-east-1")

    raw_resources = data.get("resources")
    if not isinstance(raw_resources, list) or not raw_resources:
        _fail("'resources' must be a non-empty list")

    ids, resources = {}, []
    for index, raw in enumerate(raw_resources):
        where = f"resources[{index}]"
        if not isinstance(raw, dict):
            _fail(f"{where} must be an object")
        key = raw.get("key")
        if not (isinstance(key, str) and KEY_PATTERN.match(key)):
            _fail(f"{where}.key must be lowercase letters, digits, dashes or underscores")
        if key in ids:
            _fail(f"{where}.key '{key}' is used twice")
        rtype = raw.get("resource_type")
        if not (isinstance(rtype, str) and TYPE_PATTERN.match(rtype)):
            _fail(f"{where}.resource_type must be lowercase words joined by underscores")
        aws_id = raw.get("resource_id")
        if not (isinstance(aws_id, str) and 0 < len(aws_id) <= 256):
            _fail(f"{where}.resource_id must be text of 1 to 256 characters")
        name = raw.get("name")
        if name is not None and not isinstance(name, str):
            _fail(f"{where}.name must be text")
        app = raw.get("app", "shared")
        if not (isinstance(app, str) and APP_PATTERN.match(app)):
            _fail(f"{where}.app must be lowercase letters, digits and dashes")
        config = raw.get("config", {})
        if not isinstance(config, dict):
            _fail(f"{where}.config must be an object")

        number = index + 1
        ids[key] = number
        resources.append(
            {
                "id": number,
                "resource_type": rtype,
                "resource_id": aws_id,
                "name": name,
                "app": app,
                "config": config,
            }
        )

    dependencies, seen = [], set()
    for index, raw in enumerate(data.get("dependencies", [])):
        where = f"dependencies[{index}]"
        if not isinstance(raw, dict):
            _fail(f"{where} must be an object")
        source, target, relationship = raw.get("from"), raw.get("to"), raw.get("relationship")
        if not (isinstance(source, str) and isinstance(target, str) and source in ids and target in ids):
            _fail(f"{where} refers to a resource key that does not exist")
        if source == target:
            _fail(f"{where} points a resource at itself")
        if not (isinstance(relationship, str) and 0 < len(relationship) <= 64):
            _fail(f"{where}.relationship must be text of 1 to 64 characters")
        if (source, target, relationship) in seen:
            _fail(f"{where} is listed twice")
        seen.add((source, target, relationship))
        dependencies.append(
            {
                "from_resource_id": ids[source],
                "to_resource_id": ids[target],
                "relationship": relationship,
            }
        )

    return {
        "scan": {"id": 1, "account_id": account, "region": region},
        "resources": resources,
        "dependencies": dependencies,
    }