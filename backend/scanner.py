"""
AWS Resource Scanner Module
Supports both live AWS scanning (via boto3) and mock data mode
"""

import json
import os
from datetime import datetime
from typing import Optional
from pathlib import Path

# Try to import boto3 for live scanning
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


MOCK_DATA_PATH = Path(__file__).parent.parent / "data" / "mock_aws_data.json"


def load_mock_data() -> dict:
    with open(MOCK_DATA_PATH) as f:
        return json.load(f)


def scan_s3_live(s3_client) -> list[dict]:
    buckets = []
    try:
        response = s3_client.list_buckets()
        for bucket in response.get("Buckets", []):
            name = bucket["Name"]
            info = {"name": name, "public_access": False, "encryption": False,
                    "versioning": False, "logging": False, "acl": "private",
                    "size_gb": 0, "object_count": 0}
            try:
                pab = s3_client.get_public_access_block(Bucket=name)
                cfg = pab["PublicAccessBlockConfiguration"]
                info["public_access"] = not all([
                    cfg.get("BlockPublicAcls", False),
                    cfg.get("BlockPublicPolicy", False),
                    cfg.get("RestrictPublicBuckets", False),
                ])
            except ClientError:
                info["public_access"] = True  # Assume public if can't check

            try:
                enc = s3_client.get_bucket_encryption(Bucket=name)
                info["encryption"] = bool(enc.get("ServerSideEncryptionConfiguration"))
            except ClientError:
                info["encryption"] = False

            try:
                ver = s3_client.get_bucket_versioning(Bucket=name)
                info["versioning"] = ver.get("Status") == "Enabled"
            except ClientError:
                pass

            buckets.append(info)
    except (ClientError, NoCredentialsError) as e:
        print(f"S3 scan error: {e}")
    return buckets


def scan_iam_live(iam_client) -> list[dict]:
    policies = []
    try:
        paginator = iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                version = iam_client.get_policy_version(
                    PolicyArn=policy["Arn"],
                    VersionId=policy["DefaultVersionId"]
                )
                doc = version["PolicyVersion"]["Document"]
                policies.append({
                    "policy_name": policy["PolicyName"],
                    "policy_arn": policy["Arn"],
                    "attached_to": [],
                    "statements": doc.get("Statement", [])
                })
    except (ClientError, NoCredentialsError) as e:
        print(f"IAM scan error: {e}")
    return policies


def scan_security_groups_live(ec2_client) -> list[dict]:
    groups = []
    try:
        response = ec2_client.describe_security_groups()
        for sg in response.get("SecurityGroups", []):
            inbound = []
            for perm in sg.get("IpPermissions", []):
                port = perm.get("FromPort", 0)
                proto = perm.get("IpProtocol", "tcp")
                for ip_range in perm.get("IpRanges", []):
                    inbound.append({
                        "port": port,
                        "protocol": proto,
                        "cidr": ip_range.get("CidrIp", ""),
                        "description": ip_range.get("Description", "")
                    })
            groups.append({
                "group_id": sg["GroupId"],
                "group_name": sg["GroupName"],
                "vpc_id": sg.get("VpcId", ""),
                "description": sg.get("Description", ""),
                "inbound_rules": inbound,
                "attached_instances": []
            })
    except (ClientError, NoCredentialsError) as e:
        print(f"Security group scan error: {e}")
    return groups


def scan_aws(use_mock: bool = True, region: str = "us-east-1") -> dict:
    """
    Main scan function. Returns raw AWS resource data.
    Set use_mock=False to scan live AWS (requires configured credentials).
    """
    if use_mock or not BOTO3_AVAILABLE:
        data = load_mock_data()
        data["scan_mode"] = "mock"
        data["scan_timestamp"] = datetime.utcnow().isoformat() + "Z"
        return data

    # Live scanning
    try:
        session = boto3.Session(region_name=region)
        s3 = session.client("s3")
        iam = session.client("iam")
        ec2 = session.client("ec2")

        sts = session.client("sts")
        identity = sts.get_caller_identity()

        return {
            "account_id": identity["Account"],
            "region": region,
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "scan_mode": "live",
            "s3_buckets": scan_s3_live(s3),
            "iam_policies": scan_iam_live(iam),
            "security_groups": scan_security_groups_live(ec2)
        }
    except Exception as e:
        print(f"Live scan failed, falling back to mock: {e}")
        data = load_mock_data()
        data["scan_mode"] = "mock (fallback)"
        return data
