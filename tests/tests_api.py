def risky_scan(client):
    scan = make_scan(client)
    make_resource(client, scan["id"], resource_type="security_group", resource_id="sg-1",
                  name="open-ssh",
                  config={"inbound": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                                       "cidr": "0.0.0.0/0"}]})
    make_resource(client, scan["id"], resource_type="ebs_volume", resource_id="vol-1",
                  name="old-disk", config={"state": "available", "volume_type": "gp2"})
    return scan


def test_analyze_summarises_the_findings(client):
    scan = risky_scan(client)
    r = client.post(f"/scans/{scan['id']}/analyze")
    assert r.status_code == 200
    body = r.json()
    assert body["resources_checked"] == 2
    assert body["findings"] == 3
    assert body["by_severity"] == {"high": 1, "medium": 1, "low": 1}
    assert body["by_category"] == {"risk": 1, "cost": 2}


def test_findings_come_back_sorted_with_resource_names(client):
    scan = risky_scan(client)
    client.post(f"/scans/{scan['id']}/analyze")
    findings = client.get(f"/scans/{scan['id']}/findings").json()
    assert [f["rule_id"] for f in findings] == ["sg-admin-open", "ebs-unattached", "ebs-gp2"]
    assert findings[0]["resource_name"] == "open-ssh"
    assert findings[0]["detail"]["rules"][0]["services"] == ["SSH"]


def test_findings_can_be_filtered(client):
    scan = risky_scan(client)
    client.post(f"/scans/{scan['id']}/analyze")
    base = f"/scans/{scan['id']}/findings"
    assert len(client.get(base, params={"category": "cost"}).json()) == 2
    assert len(client.get(base, params={"severity": "high"}).json()) == 1
    assert client.get(base, params={"severity": "urgent"}).status_code == 422


def test_analysing_twice_does_not_duplicate_findings(client):
    scan = risky_scan(client)
    client.post(f"/scans/{scan['id']}/analyze")
    client.post(f"/scans/{scan['id']}/analyze")
    assert len(client.get(f"/scans/{scan['id']}/findings").json()) == 3


def test_a_scan_with_no_resources_has_no_findings(client):
    scan = make_scan(client)
    body = client.post(f"/scans/{scan['id']}/analyze").json()
    assert body["findings"] == 0
    assert client.get(f"/scans/{scan['id']}/findings").json() == []


def test_findings_endpoints_return_404_for_a_missing_scan(client):
    assert client.post("/scans/999/analyze").status_code == 404
    assert client.get("/scans/999/findings").status_code == 404