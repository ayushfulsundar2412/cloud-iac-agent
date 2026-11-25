import sys
from pathlib import Path

from app.reporting import build_report, llm_explainer, render_markdown

scan = {"id": 1, "account_id": "123456789012", "region": "us-east-1"}

# Invented data in the shape of database rows.
resources = [
    {"id": 1, "resource_type": "security_group", "resource_id": "sg-0001", "name": "web-sg",
     "app": "shared", "config": {"inbound": [
         {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},
         {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr": "0.0.0.0/0"}]}},
    {"id": 2, "resource_type": "s3_bucket", "resource_id": "customer-uploads", "name": "customer-uploads",
     "app": "website", "config": {"public_access_block": False}},
    {"id": 3, "resource_type": "rds_instance", "resource_id": "orders-db", "name": "orders-db",
     "app": "billing", "config": {"publicly_accessible": True, "backup_retention_days": 0,
                                  "storage_encrypted": False}},
    {"id": 4, "resource_type": "ec2_instance", "resource_id": "i-0aaa111", "name": "web-1",
     "app": "website", "config": {"metadata_http_tokens": "optional"}},
    {"id": 5, "resource_type": "ebs_volume", "resource_id": "vol-0001", "name": "old-data",
     "app": "billing", "config": {"state": "available", "volume_type": "gp2", "size_gb": 100}},
    {"id": 6, "resource_type": "ebs_volume", "resource_id": "vol-0002", "name": "web-1-root",
     "app": "website", "config": {"state": "in-use", "volume_type": "gp2", "size_gb": 500}},
    {"id": 7, "resource_type": "ebs_snapshot", "resource_id": "snap-0001", "name": "snap-2023",
     "app": "billing", "config": {"age_days": 400, "size_gb": 200}},
    {"id": 8, "resource_type": "elastic_ip", "resource_id": "eipalloc-0001", "name": "unused-ip",
     "app": "shared", "config": {"associated": False}},
    {"id": 9, "resource_type": "vpc", "resource_id": "vpc-0001", "name": "main-vpc",
     "app": "shared", "config": {}},
    {"id": 10, "resource_type": "security_group", "resource_id": "sg-0002", "name": "mystery-sg",
     "app": "shared", "config": {}},
]

use_llm = "--llm" in sys.argv
report = build_report(scan, resources, explainer=llm_explainer if use_llm else None,
                      generated_at="demo run")
text = render_markdown(report)

out = Path("build/report.md")
out.parent.mkdir(exist_ok=True)
out.write_text(text, encoding="utf-8")
print(text.encode("ascii", "replace").decode())