from app.findings.rules import is_world_admin_rule
from app.generation.hcl import hcl_str


def _import_block(tf_type: str, local: str, import_id: str) -> str:
    return f"import {{\n  to = {tf_type}.{local}\n  id = {hcl_str(import_id)}\n}}"


def needs_admin_cidr(resource: dict) -> bool:
    """True if a security group has a rule the 'fix' mode would restrict."""
    if resource.get("resource_type") != "security_group":
        return False
    config = resource.get("config")
    inbound = config.get("inbound", []) if isinstance(config, dict) else []
    if not isinstance(inbound, list):
        return False
    return any(is_world_admin_rule(rule) for rule in inbound)


def _s3_bucket(r: dict, local: str, refs: dict, fix: bool = False):
    bucket = r.get("resource_id")
    if not bucket:
        return [], [f"resource {r['id']}: s3 bucket has no name"]
    cfg = r.get("config") or {}
    blocks = [
        f'resource "aws_s3_bucket" "{local}" {{\n  bucket = {hcl_str(bucket)}\n}}',
        _import_block("aws_s3_bucket", local, bucket),
    ]
    if cfg.get("versioning") is True:
        blocks += [
            f'resource "aws_s3_bucket_versioning" "{local}" {{\n'
            f"  bucket = aws_s3_bucket.{local}.id\n"
            "  versioning_configuration {\n"
            '    status = "Enabled"\n'
            "  }\n"
            "}",
            _import_block("aws_s3_bucket_versioning", local, bucket),
        ]
    if fix and cfg.get("public_access_block") is False:
        blocks.append(
            f'resource "aws_s3_bucket_public_access_block" "{local}" {{\n'
            "  # Proposed fix: block all public access to this bucket\n"
            f"  bucket                  = aws_s3_bucket.{local}.id\n"
            "  block_public_acls       = true\n"
            "  block_public_policy     = true\n"
            "  ignore_public_acls      = true\n"
            "  restrict_public_buckets = true\n"
            "}"
        )
    return blocks, []


def _security_group(r: dict, local: str, refs: dict, fix: bool = False):
    name = r.get("name")
    if not name:
        return [], [f"resource {r['id']}: security group has no name"]
    cfg = r.get("config") or {}
    gaps = []
    lines = [f'resource "aws_security_group" "{local}" {{', f"  name = {hcl_str(name)}"]
    if cfg.get("description"):
        lines.append(f"  description = {hcl_str(cfg['description'])}")
    for rule in cfg.get("inbound", []):
        try:
            port = rule.get("port")
            from_port = int(rule.get("from_port", port))
            to_port = int(rule.get("to_port", port))
            cidr = str(rule["cidr"])
            if not (0 <= from_port <= 65535 and 0 <= to_port <= 65535):
                raise ValueError("port out of range")
        except (KeyError, TypeError, ValueError):
            gaps.append(f"resource {r['id']}: skipped an inbound rule that could not be read")
            continue
        restrict = fix and is_world_admin_rule(rule)
        lines += ["", "  ingress {"]
        if restrict:
            lines.append("    # Proposed fix: this rule was open to the whole internet")
        lines += [
            f"    from_port   = {from_port}",
            f"    to_port     = {to_port}",
            f"    protocol    = {hcl_str(rule.get('protocol', 'tcp'))}",
            "    cidr_blocks = [var.admin_cidr]" if restrict else f"    cidr_blocks = [{hcl_str(cidr)}]",
            "  }",
        ]
    lines.append("}")
    blocks = ["\n".join(lines), _import_block("aws_security_group", local, r["resource_id"])]
    return blocks, gaps


def _ec2_instance(r: dict, local: str, refs: dict, fix: bool = False):
    cfg = r.get("config") or {}
    ami, instance_type = cfg.get("ami"), cfg.get("instance_type")
    missing = [k for k, v in (("ami", ami), ("instance_type", instance_type)) if not v]
    if missing:
        return [], [f"resource {r['id']}: instance skipped, missing {', '.join(missing)}"]
    lines = [
        f'resource "aws_instance" "{local}" {{',
        f"  ami           = {hcl_str(ami)}",
        f"  instance_type = {hcl_str(instance_type)}",
    ]
    if refs.get("security_groups"):
        ids = ", ".join(refs["security_groups"])
        lines.append(f"  vpc_security_group_ids = [{ids}]")
    if fix and cfg.get("metadata_http_tokens") == "optional":
        lines += [
            "",
            "  # Proposed fix: require the newer metadata service (IMDSv2)",
            "  metadata_options {",
            '    http_tokens = "required"',
            "  }",
        ]
    if r.get("name"):
        lines += ["", "  tags = {", f"    Name = {hcl_str(r['name'])}", "  }"]
    lines.append("}")
    blocks = ["\n".join(lines), _import_block("aws_instance", local, r["resource_id"])]
    return blocks, []


# resource_type in our database -> the function that writes its Terraform
RENDERERS = {
    "s3_bucket": _s3_bucket,
    "security_group": _security_group,
    "ec2_instance": _ec2_instance,
}