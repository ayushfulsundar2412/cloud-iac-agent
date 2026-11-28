import json
from pathlib import Path

import pytest

from app.estate import EstateError, load_estate, parse_estate

SAMPLE = Path(__file__).parent.parent / "sample" / "estate.json"


def base():
    return {
        "scan": {"account_id": "123456789012", "region": "us-east-1"},
        "resources": [
            {"key": "a", "resource_type": "s3_bucket", "resource_id": "bucket-a"},
            {"key": "b", "resource_type": "security_group", "resource_id": "sg-1",
             "name": "sg-b", "app": "billing", "config": {"inbound": []}},
        ],
        "dependencies": [{"from": "b", "to": "a", "relationship": "uses"}],
    }


def test_the_sample_estate_loads():
    estate = load_estate(SAMPLE)
    assert len(estate["resources"]) == 15
    assert [r["id"] for r in estate["resources"]] == list(range(1, 16))
    assert estate["scan"] == {"id": 1, "account_id": "123456789012", "region": "us-east-1"}
    ids = {r["id"] for r in estate["resources"]}
    for dep in estate["dependencies"]:
        assert dep["from_resource_id"] in ids and dep["to_resource_id"] in ids


def test_defaults_are_filled_in():
    first = parse_estate(base())["resources"][0]
    assert first["app"] == "shared"
    assert first["config"] == {}
    assert first["name"] is None


def test_dependencies_are_turned_from_keys_into_ids():
    dep = parse_estate(base())["dependencies"][0]
    assert (dep["from_resource_id"], dep["to_resource_id"]) == (2, 1)


def test_a_file_that_is_not_an_object_is_rejected():
    with pytest.raises(EstateError, match="JSON object"):
        parse_estate([])


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d.pop("scan"), "scan"),
        (lambda d: d["scan"].update(account_id="abc"), "12 digits"),
        (lambda d: d["scan"].update(region="mars"), "region"),
        (lambda d: d.update(resources=[]), "resources"),
        (lambda d: d["resources"].append("oops"), "must be an object"),
        (lambda d: d["resources"][0].update(key="Has Spaces"), "key"),
        (lambda d: d["resources"][1].update(key="a"), "used twice"),
        (lambda d: d["resources"][0].pop("resource_type"), "resource_type"),
        (lambda d: d["resources"][0].update(resource_id=""), "resource_id"),
        (lambda d: d["resources"][0].update(app="../evil"), "app"),
        (lambda d: d["resources"][0].update(config="x"), "config"),
        (lambda d: d["resources"][0].update(name=5), "name"),
        (lambda d: d["dependencies"][0].update(to="zzz"), "does not exist"),
        (lambda d: d["dependencies"][0].update(to="b"), "itself"),
        (lambda d: d["dependencies"][0].update(relationship=""), "relationship"),
        (lambda d: d["dependencies"].append(dict(d["dependencies"][0])), "twice"),
    ],
)
def test_invalid_estates_are_rejected_with_a_clear_message(mutate, expected):
    data = base()
    mutate(data)
    with pytest.raises(EstateError) as excinfo:
        parse_estate(data)
    assert expected in str(excinfo.value)


def test_a_file_that_is_not_json_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(EstateError, match="not valid JSON"):
        load_estate(path)


def test_an_oversized_file_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "big.json"
    path.write_text(json.dumps(base()), encoding="utf-8")
    monkeypatch.setattr("app.estate.MAX_FILE_BYTES", 10)
    with pytest.raises(EstateError, match="too large"):
        load_estate(path)