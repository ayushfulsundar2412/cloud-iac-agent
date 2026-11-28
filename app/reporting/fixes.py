# For every rule: can Terraform fix it, and how?
#   auto   = a template writes the fix
#   person = needs a human decision, so no code is written
#   later  = needs a template that does not exist yet
RULE_FIX = {
    "sg-admin-open": (
        "auto",
        "Replaces the open source range with a variable, var.admin_cidr, that a person must set to "
        "the office or VPN range. Check who connects before applying, or people may be locked out.",
    ),
    "s3-no-public-access-block": (
        "auto",
        "Adds a public access block with all four protections turned on.",
    ),
    "ec2-imdsv1": (
        "auto",
        "Requires the newer metadata service (IMDSv2) on the instance.",
    ),
    "sg-db-ports-open": (
        "person",
        "Which application group should reach the database is a decision for a person.",
    ),
    "sg-all-traffic-open": (
        "person",
        "Which ports and sources are really needed is a decision for a person.",
    ),
    "ebs-unattached": ("person", "Deleting a disk is a decision for a person."),
    "snapshot-old": ("person", "Deleting backups is a decision for a person."),
    "eip-unassociated": ("person", "Releasing an address is a decision for a person."),
    "rds-public": ("later", "Terraform for databases is not generated yet."),
    "rds-no-backups": ("later", "Terraform for databases is not generated yet."),
    "rds-unencrypted": (
        "later",
        "Terraform for databases is not generated yet, and encryption needs a planned migration.",
    ),
    "ebs-gp2": ("later", "Terraform for disks is not generated yet."),
}


def fix_status(rule_id: str, resource_id: int, generated_ids: set) -> dict:
    kind, note = RULE_FIX[rule_id]
    if kind == "auto":
        if resource_id in generated_ids:
            return {"status": "proposed", "note": note}
        return {
            "status": "blocked",
            "note": "The resource itself could not be generated yet, see the Terraform gaps.",
        }
    if kind == "person":
        return {"status": "needs a person", "note": note}
    return {"status": "not yet supported", "note": note}