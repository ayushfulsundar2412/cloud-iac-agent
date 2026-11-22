from app.findings.engine import rule

WORLD = {"0.0.0.0/0", "::/0"}  #The whole internet {ipv4 add., ipv6 add.}
ADMIN_PORTS = {22: "SSH", 3389: "remote desktop"} #{Remote login to Linux, Remote login to Windows}
DATABASE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    1521: "Oracle",
    27017: "MongoDB",
}  #Same for common databases ports
SNAPSHOT_MAX_AGE_DAYS = 90  # a policy choice, not an AWS rule. Can change it later on based on need

#Keeps only the rules that are open to the whole internet
def _world_rules(config: dict) -> list:
    return [p for p in config.get("inbound", []) if str(p.get("cidr")) in WORLD]

# This is Unknown is not bad where unreadable ports doesnt become an accusation
def _port_range(perm: dict):
    low = perm.get("from_port", perm.get("port"))
    high = perm.get("to_port", perm.get("port"))
    try:
        return int(low), int(high)
    except (TypeError, ValueError):
        return None

#shared engine behind two rules: one asks about admin ports, one asks about database ports
def _exposed(config: dict, watched: dict) -> list:
    hits = []
    for perm in _world_rules(config):
        if str(perm.get("protocol", "tcp")) != "tcp": #If not tcp skip it as these ports use tcp
            continue
        bounds = _port_range(perm)
        if bounds is None:
            continue
        low, high = bounds
        services = [name for port, name in watched.items() if low <= port <= high]
        if services:
            hits.append({"ports": f"{low}-{high}", "services": services, "source": perm["cidr"]})
    return hits


def _is_zero(value) -> bool:
    return type(value) in (int, float) and value == 0  # False is not zero days

#Security group rules:
@rule("sg-admin-open", "high", "risk", ("security_group",),
      "Admin ports are open to the internet")
def sg_admin_open(config):
    hits = _exposed(config, ADMIN_PORTS)
    return {"rules": hits} if hits else None


@rule("sg-db-ports-open", "high", "risk", ("security_group",),
      "Database ports are open to the internet")
def sg_db_ports_open(config):
    hits = _exposed(config, DATABASE_PORTS)
    return {"rules": hits} if hits else None


@rule("sg-all-traffic-open", "high", "risk", ("security_group",),
      "All traffic is allowed from the internet")
def sg_all_traffic_open(config):
    sources = [p["cidr"] for p in _world_rules(config) if str(p.get("protocol")) == "-1"]
    return {"sources": sources} if sources else None

#S3 rules:
@rule("s3-no-public-access-block", "high", "risk", ("s3_bucket",),
      "Bucket has no full public access block")
def s3_no_public_access_block(config):
    if config.get("public_access_block") is False:
        return {"public_access_block": False}
    return None


@rule("rds-public", "high", "risk", ("rds_instance",),
      "Database can be reached from the internet")
def rds_public(config):
    if config.get("publicly_accessible") is True:
        return {"publicly_accessible": True}
    return None


@rule("rds-no-backups", "medium", "risk", ("rds_instance",),
      "Database has no automatic backups")
def rds_no_backups(config):
    if _is_zero(config.get("backup_retention_days")):
        return {"backup_retention_days": 0}
    return None


@rule("rds-unencrypted", "medium", "risk", ("rds_instance",),
      "Database storage is not encrypted")
def rds_unencrypted(config):
    if config.get("storage_encrypted") is False:
        return {"storage_encrypted": False}
    return None


@rule("ec2-imdsv1", "medium", "risk", ("ec2_instance",),
      "Server still allows the older metadata service (IMDSv1)")
def ec2_imdsv1(config):
    if config.get("metadata_http_tokens") == "optional":
        return {"metadata_http_tokens": "optional"}
    return None


@rule("ebs-unattached", "medium", "cost", ("ebs_volume",),
      "Disk is not attached to anything")
def ebs_unattached(config):
    if config.get("state") == "available":
        return {"state": "available"}
    return None


@rule("ebs-gp2", "low", "cost", ("ebs_volume",),
      "Disk uses the older gp2 type")
def ebs_gp2(config):
    if config.get("volume_type") == "gp2":
        return {"volume_type": "gp2"}
    return None


@rule("snapshot-old", "low", "cost", ("ebs_snapshot",),
      "Snapshot is older than the retention limit")
def snapshot_old(config):
    age = config.get("age_days")
    if type(age) in (int, float) and age > SNAPSHOT_MAX_AGE_DAYS:
        return {"age_days": age, "limit_days": SNAPSHOT_MAX_AGE_DAYS}
    return None


@rule("eip-unassociated", "low", "cost", ("elastic_ip",),
      "Public IP address is not in use")
def eip_unassociated(config):
    if config.get("associated") is False:
        return {"associated": False}
    return None 