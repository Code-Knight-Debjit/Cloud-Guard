"""
Risk Scoring Engine
Calculates dynamic risk scores based on exposure, permissions, and impact.
"""

from dataclasses import dataclass
from typing import Optional


THREAT_MAP = {
    "public_s3": {
        "attack_type": "Data Exfiltration",
        "mitre_tactic": "TA0010 - Exfiltration",
        "mitre_technique": "T1530 - Data from Cloud Storage",
        "description": "Publicly accessible S3 buckets allow unauthenticated users to list and download all objects, enabling mass data theft.",
        "real_world_example": "Capital One breach (2019) - exposed 100M+ customer records from misconfigured S3"
    },
    "s3_no_encryption": {
        "attack_type": "Data Exposure at Rest",
        "mitre_tactic": "TA0009 - Collection",
        "mitre_technique": "T1530 - Data from Cloud Storage",
        "description": "Unencrypted S3 data is readable in plaintext if access controls fail, violating compliance requirements.",
        "real_world_example": "Numerous HIPAA violations traced to unencrypted S3 buckets"
    },
    "iam_wildcard": {
        "attack_type": "Privilege Escalation",
        "mitre_tactic": "TA0004 - Privilege Escalation",
        "mitre_technique": "T1078 - Valid Accounts / T1098 - Account Manipulation",
        "description": "Wildcard IAM permissions grant unrestricted access to all AWS services and resources, enabling lateral movement and full account takeover.",
        "real_world_example": "Tesla cryptojacking incident (2018) - attackers exploited over-permissioned IAM to mine cryptocurrency"
    },
    "iam_s3_wildcard": {
        "attack_type": "Unrestricted Storage Access",
        "mitre_tactic": "TA0004 - Privilege Escalation",
        "mitre_technique": "T1530 - Data from Cloud Storage",
        "description": "S3 wildcard permissions allow reading, writing, and deleting from all buckets, enabling ransomware and data theft.",
        "real_world_example": "Multiple ransomware attacks targeting S3 with wildcard policies"
    },
    "open_ssh": {
        "attack_type": "Brute Force / Unauthorized Access",
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1110 - Brute Force / T1021 - Remote Services",
        "description": "Exposing SSH to 0.0.0.0/0 enables internet-scale brute force attacks and exploitation of SSH vulnerabilities.",
        "real_world_example": "Rocke group (2018) - compromised EC2 instances via exposed SSH for cryptomining"
    },
    "open_rdp": {
        "attack_type": "Remote Desktop Exploitation",
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1021.001 - Remote Desktop Protocol",
        "description": "Publicly exposed RDP is a primary ransomware entry vector. BlueKeep and DejaBlue vulnerabilities enable unauthenticated RCE.",
        "real_world_example": "WannaCry and NotPetya spread partly via exposed RDP and SMB"
    },
    "open_database": {
        "attack_type": "Database Compromise",
        "mitre_tactic": "TA0006 - Credential Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "description": "Exposing database ports publicly enables direct credential attacks, SQL injection from internet, and data exfiltration.",
        "real_world_example": "MongoDB apocalypse (2017) - 27,000+ unprotected databases wiped by attackers"
    },
    "open_port_generic": {
        "attack_type": "Service Exploitation",
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "description": "Exposing services to the internet increases attack surface and enables exploitation of unpatched vulnerabilities.",
        "real_world_example": "Log4Shell exploitation via publicly exposed services"
    }
}


ATTACK_CHAINS = [
    {
        "id": "chain_1",
        "name": "Full Account Compromise Chain",
        "severity": "CRITICAL",
        "steps": [
            {
                "step": 1,
                "resource": "EC2 Security Group",
                "action": "Initial Access via exposed SSH (port 22 → 0.0.0.0/0)",
                "technique": "T1110 - Brute Force",
                "icon": "🌐"
            },
            {
                "step": 2,
                "resource": "EC2 Instance",
                "action": "Attacker gains shell access, discovers attached IAM role",
                "technique": "T1078 - Valid Accounts",
                "icon": "💻"
            },
            {
                "step": 3,
                "resource": "IAM Role (DevOpsFullAccess)",
                "action": "Exploits wildcard IAM policy (*:*) for privilege escalation",
                "technique": "T1098 - Account Manipulation",
                "icon": "🔑"
            },
            {
                "step": 4,
                "resource": "S3 Bucket (prod-customer-data-backup)",
                "action": "Exfiltrates 245GB of customer PII data from public bucket",
                "technique": "T1530 - Data from Cloud Storage",
                "icon": "📦"
            },
            {
                "step": 5,
                "resource": "AWS Account",
                "action": "Creates backdoor IAM user, deploys cryptominer, demands ransom",
                "technique": "T1496 - Resource Hijacking",
                "icon": "💀"
            }
        ],
        "business_impact": "Full data breach, regulatory fines (GDPR/HIPAA), service disruption, reputational damage",
        "estimated_cost": "$4.2M - $8.5M (avg. breach cost + fines)",
        "triggers": ["open_ssh", "iam_wildcard", "public_s3"]
    },
    {
        "id": "chain_2",
        "name": "Database Ransomware Chain",
        "severity": "CRITICAL",
        "steps": [
            {
                "step": 1,
                "resource": "EC2 Security Group (db-server-sg)",
                "action": "Discovers exposed MySQL/PostgreSQL (3306/5432 → 0.0.0.0/0)",
                "technique": "T1046 - Network Service Scanning",
                "icon": "🔍"
            },
            {
                "step": 2,
                "resource": "Database Server",
                "action": "Brute forces credentials or exploits CVE in database engine",
                "technique": "T1110 - Brute Force",
                "icon": "🗄️"
            },
            {
                "step": 3,
                "resource": "Database",
                "action": "Exfiltrates all tables, drops database, leaves ransom note",
                "technique": "T1485 - Data Destruction",
                "icon": "💀"
            }
        ],
        "business_impact": "Data loss, operational downtime, regulatory violations",
        "estimated_cost": "$1.5M - $3M",
        "triggers": ["open_database"]
    }
]


@dataclass
class Finding:
    resource_type: str
    resource_name: str
    resource_id: str
    issue_type: str
    issue_title: str
    description: str
    risk_score: int
    risk_label: str
    exposure_score: int
    permission_score: int
    impact_score: int
    threat_key: str
    attack_type: str
    mitre_tactic: str
    mitre_technique: str
    real_world_example: str
    remediation_steps: list[str]
    remediation_priority: str
    affected_chain_ids: list[str]


def calculate_risk_score(exposure: int, permission: int, impact: int) -> tuple[int, str]:
    """
    Dynamic risk score calculation.
    Score = (Exposure * 0.35) + (Permission * 0.35) + (Impact * 0.30)
    Weighted: exposure and permission are equal primary drivers, impact amplifies.
    """
    raw = (exposure * 0.35) + (permission * 0.35) + (impact * 0.30)
    score = min(100, int(raw))

    if score >= 85:
        label = "CRITICAL"
    elif score >= 65:
        label = "HIGH"
    elif score >= 40:
        label = "MEDIUM"
    else:
        label = "LOW"

    return score, label


def analyze_s3(buckets: list[dict]) -> list[Finding]:
    findings = []

    for bucket in buckets:
        name = bucket["name"]

        if bucket.get("public_access"):
            # Public S3 bucket
            # Exposure: fully internet-exposed = 95
            # Permission: depends on acl (read vs read-write)
            acl = bucket.get("acl", "")
            perm_score = 95 if "write" in acl else 80
            # Impact: based on size
            size = bucket.get("size_gb", 0)
            impact_score = min(100, 60 + (size // 10))

            score, label = calculate_risk_score(95, perm_score, impact_score)
            threat = THREAT_MAP["public_s3"]

            findings.append(Finding(
                resource_type="S3 Bucket",
                resource_name=name,
                resource_id=f"arn:aws:s3:::{name}",
                issue_type="PUBLIC_ACCESS",
                issue_title="S3 Bucket Publicly Accessible",
                description=f"Bucket '{name}' ({size}GB, {bucket.get('object_count', 0):,} objects) is publicly accessible via ACL '{acl}'.",
                risk_score=score,
                risk_label=label,
                exposure_score=95,
                permission_score=perm_score,
                impact_score=impact_score,
                threat_key="public_s3",
                attack_type=threat["attack_type"],
                mitre_tactic=threat["mitre_tactic"],
                mitre_technique=threat["mitre_technique"],
                real_world_example=threat["real_world_example"],
                remediation_steps=[
                    "Enable S3 Block Public Access at bucket level",
                    "Remove public-read/public-read-write ACL grants",
                    "Enable S3 Block Public Access at account level",
                    "Use pre-signed URLs for temporary public access instead",
                    "Enable S3 access logging to detect unauthorized access"
                ],
                remediation_priority="IMMEDIATE",
                affected_chain_ids=["chain_1"]
            ))

        if not bucket.get("encryption"):
            # No encryption at rest
            exp_score = 30 if not bucket.get("public_access") else 70
            perm_score = 50
            impact_score = 65

            score, label = calculate_risk_score(exp_score, perm_score, impact_score)
            threat = THREAT_MAP["s3_no_encryption"]

            findings.append(Finding(
                resource_type="S3 Bucket",
                resource_name=name,
                resource_id=f"arn:aws:s3:::{name}",
                issue_type="NO_ENCRYPTION",
                issue_title="S3 Bucket Encryption Disabled",
                description=f"Bucket '{name}' has no server-side encryption. Data stored in plaintext.",
                risk_score=score,
                risk_label=label,
                exposure_score=exp_score,
                permission_score=perm_score,
                impact_score=impact_score,
                threat_key="s3_no_encryption",
                attack_type=threat["attack_type"],
                mitre_tactic=threat["mitre_tactic"],
                mitre_technique=threat["mitre_technique"],
                real_world_example=threat["real_world_example"],
                remediation_steps=[
                    "Enable S3 default encryption (SSE-S3 or SSE-KMS)",
                    "Use SSE-KMS for sensitive data with customer-managed keys",
                    "Enable bucket key to reduce KMS API costs",
                    "Implement S3 bucket policy to enforce encrypted uploads only"
                ],
                remediation_priority="HIGH",
                affected_chain_ids=[]
            ))

    return findings


def analyze_iam(policies: list[dict]) -> list[Finding]:
    findings = []

    for policy in policies:
        name = policy["policy_name"]
        arn = policy.get("policy_arn", "")
        attached_to = policy.get("attached_to", [])

        for statement in policy.get("statements", []):
            if statement.get("effect") != "Allow":
                continue

            actions = statement.get("action", [])
            resources = statement.get("resource", [])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            # Full wildcard: Action=* Resource=*
            if "*" in actions and "*" in resources:
                attachment_count = len(attached_to)
                exp_score = min(100, 75 + (attachment_count * 5))
                perm_score = 100  # Maximum - full admin
                impact_score = 100  # Full account takeover possible

                score, label = calculate_risk_score(exp_score, perm_score, impact_score)
                threat = THREAT_MAP["iam_wildcard"]

                findings.append(Finding(
                    resource_type="IAM Policy",
                    resource_name=name,
                    resource_id=arn,
                    issue_type="WILDCARD_PERMISSIONS",
                    issue_title="IAM Policy with Full Wildcard Permissions (Action:* Resource:*)",
                    description=f"Policy '{name}' grants unrestricted access to ALL AWS services and resources. Attached to: {', '.join(attached_to)}.",
                    risk_score=score,
                    risk_label=label,
                    exposure_score=exp_score,
                    permission_score=perm_score,
                    impact_score=impact_score,
                    threat_key="iam_wildcard",
                    attack_type=threat["attack_type"],
                    mitre_tactic=threat["mitre_tactic"],
                    mitre_technique=threat["mitre_technique"],
                    real_world_example=threat["real_world_example"],
                    remediation_steps=[
                        "Apply principle of least privilege - grant only required permissions",
                        "Replace wildcard with specific service actions (e.g., s3:GetObject, ec2:StartInstances)",
                        "Use AWS IAM Access Analyzer to identify unused permissions",
                        "Implement permission boundaries to cap maximum permissions",
                        "Enable AWS CloudTrail to audit API calls by this policy",
                        "Use AWS Organizations SCPs to prevent future wildcard policies"
                    ],
                    remediation_priority="IMMEDIATE",
                    affected_chain_ids=["chain_1"]
                ))

            # S3 wildcard
            elif any("s3:*" in a or ("s3" in a and "*" in a) for a in actions) and "*" in resources:
                exp_score = 70
                perm_score = 85
                impact_score = 80

                score, label = calculate_risk_score(exp_score, perm_score, impact_score)
                threat = THREAT_MAP["iam_s3_wildcard"]

                findings.append(Finding(
                    resource_type="IAM Policy",
                    resource_name=name,
                    resource_id=arn,
                    issue_type="S3_WILDCARD",
                    issue_title="IAM Policy with Unrestricted S3 Access",
                    description=f"Policy '{name}' grants s3:* on all resources (*). Attached to: {', '.join(attached_to)}.",
                    risk_score=score,
                    risk_label=label,
                    exposure_score=exp_score,
                    permission_score=perm_score,
                    impact_score=impact_score,
                    threat_key="iam_s3_wildcard",
                    attack_type=threat["attack_type"],
                    mitre_tactic=threat["mitre_tactic"],
                    mitre_technique=threat["mitre_technique"],
                    real_world_example=threat["real_world_example"],
                    remediation_steps=[
                        "Restrict to specific S3 buckets (arn:aws:s3:::bucket-name/*)",
                        "Separate read (s3:GetObject) from write (s3:PutObject) permissions",
                        "Avoid s3:DeleteObject unless explicitly required",
                        "Use S3 bucket policies as a secondary access control layer"
                    ],
                    remediation_priority="HIGH",
                    affected_chain_ids=["chain_1"]
                ))

    return findings


def analyze_security_groups(groups: list[dict]) -> list[Finding]:
    findings = []

    DANGEROUS_PORTS = {
        22: ("SSH", "open_ssh", 90, 85),
        3389: ("RDP", "open_rdp", 95, 90),
        3306: ("MySQL", "open_database", 85, 88),
        5432: ("PostgreSQL", "open_database", 85, 88),
        27017: ("MongoDB", "open_database", 88, 90),
        6379: ("Redis", "open_database", 85, 85),
        23: ("Telnet", "open_port_generic", 95, 70),
        21: ("FTP", "open_port_generic", 90, 65),
    }

    for sg in groups:
        sg_name = sg["group_name"]
        sg_id = sg["group_id"]
        instance_count = len(sg.get("attached_instances", []))

        for rule in sg.get("inbound_rules", []):
            port = rule.get("port", 0)
            cidr = rule.get("cidr", "")

            if cidr not in ("0.0.0.0/0", "::/0"):
                continue

            if port in DANGEROUS_PORTS:
                port_name, threat_key, exp_base, impact_base = DANGEROUS_PORTS[port]
                # Amplify by number of instances
                exp_score = min(100, exp_base + (instance_count * 2))
                impact_score = min(100, impact_base + (instance_count * 3))
                perm_score = 80

                score, label = calculate_risk_score(exp_score, perm_score, impact_score)
                threat = THREAT_MAP[threat_key]

                findings.append(Finding(
                    resource_type="Security Group",
                    resource_name=sg_name,
                    resource_id=sg_id,
                    issue_type=f"OPEN_PORT_{port}",
                    issue_title=f"Port {port} ({port_name}) Exposed to Internet (0.0.0.0/0)",
                    description=f"Security group '{sg_name}' allows inbound {port_name} from any IP address. Affects {instance_count} instance(s).",
                    risk_score=score,
                    risk_label=label,
                    exposure_score=exp_score,
                    permission_score=perm_score,
                    impact_score=impact_score,
                    threat_key=threat_key,
                    attack_type=threat["attack_type"],
                    mitre_tactic=threat["mitre_tactic"],
                    mitre_technique=threat["mitre_technique"],
                    real_world_example=threat["real_world_example"],
                    remediation_steps=get_port_remediation(port, port_name),
                    remediation_priority="IMMEDIATE" if port in (22, 3389, 3306) else "HIGH",
                    affected_chain_ids=["chain_1"] if port == 22 else ["chain_2"] if port in (3306, 5432, 27017) else []
                ))

    return findings


def get_port_remediation(port: int, service: str) -> list[str]:
    base = [
        f"Restrict inbound {service} access to specific IP ranges or VPN CIDR",
        "Use AWS Systems Manager Session Manager instead of direct SSH access",
        "Place resources in private subnets with NAT gateway for outbound traffic",
    ]

    extras = {
        22: [
            "Enable EC2 Instance Connect for temporary key-based access",
            "Implement fail2ban or equivalent brute force protection",
            "Use AWS VPN or Direct Connect for administrative access"
        ],
        3389: [
            "Use AWS WorkSpaces or bastion host for RDP access",
            "Enable NLA (Network Level Authentication) on Windows instances",
            "Apply Windows security patches to prevent BlueKeep/DejaBlue exploitation"
        ],
        3306: [
            "Use RDS with VPC security groups restricted to application tier only",
            "Enable RDS encryption at rest and in transit",
            "Use IAM database authentication instead of static credentials"
        ],
        5432: [
            "Restrict to application server security group ID (not CIDR)",
            "Enable pg_audit for comprehensive query logging",
            "Use SSL certificates for all database connections"
        ],
        27017: [
            "Enable MongoDB authentication (not disabled by default in older versions)",
            "Use MongoDB Atlas with built-in network isolation",
            "Enable TLS/SSL for all MongoDB connections"
        ]
    }

    return base + extras.get(port, [])


def get_active_attack_chains(findings: list[Finding]) -> list[dict]:
    """Return attack chains that are triggered by current findings."""
    active_threat_keys = {f.threat_key for f in findings}
    active_chains = []

    for chain in ATTACK_CHAINS:
        triggers = set(chain["triggers"])
        matched = triggers.intersection(active_threat_keys)
        if len(matched) >= 2:  # Chain is active if 2+ triggers present
            chain_copy = dict(chain)
            chain_copy["matched_triggers"] = list(matched)
            chain_copy["completion_pct"] = int((len(matched) / len(triggers)) * 100)
            active_chains.append(chain_copy)

    return active_chains


def calculate_overall_score(findings: list[Finding]) -> dict:
    if not findings:
        return {"score": 100, "grade": "A", "label": "Secure"}

    # Weighted average, critical findings dominate
    weights = {"CRITICAL": 4, "HIGH": 2, "MEDIUM": 1, "LOW": 0.5}
    total_weight = sum(weights.get(f.risk_label, 1) for f in findings)
    weighted_sum = sum(f.risk_score * weights.get(f.risk_label, 1) for f in findings)

    avg_risk = weighted_sum / total_weight if total_weight > 0 else 0
    security_score = max(0, 100 - avg_risk)

    if security_score >= 90:
        grade, label = "A", "Excellent"
    elif security_score >= 75:
        grade, label = "B", "Good"
    elif security_score >= 60:
        grade, label = "C", "Fair"
    elif security_score >= 40:
        grade, label = "D", "Poor"
    else:
        grade, label = "F", "Critical Risk"

    severity_breakdown = {
        "CRITICAL": sum(1 for f in findings if f.risk_label == "CRITICAL"),
        "HIGH": sum(1 for f in findings if f.risk_label == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f.risk_label == "MEDIUM"),
        "LOW": sum(1 for f in findings if f.risk_label == "LOW"),
    }

    return {
        "security_score": round(security_score, 1),
        "grade": grade,
        "label": label,
        "total_findings": len(findings),
        "severity_breakdown": severity_breakdown,
        "highest_risk_score": max(f.risk_score for f in findings),
        "average_risk_score": round(sum(f.risk_score for f in findings) / len(findings), 1)
    }


def run_full_analysis(use_mock: bool = True) -> dict:
    """Run complete scan and analysis. Returns structured report."""
    from scanner import scan_aws

    raw_data = scan_aws(use_mock=use_mock)

    s3_findings = analyze_s3(raw_data.get("s3_buckets", []))
    iam_findings = analyze_iam(raw_data.get("iam_policies", []))
    sg_findings = analyze_security_groups(raw_data.get("security_groups", []))

    all_findings = s3_findings + iam_findings + sg_findings
    all_findings.sort(key=lambda f: f.risk_score, reverse=True)

    active_chains = get_active_attack_chains(all_findings)
    overall = calculate_overall_score(all_findings)

    return {
        "scan_info": {
            "account_id": raw_data.get("account_id"),
            "region": raw_data.get("region"),
            "timestamp": raw_data.get("scan_timestamp"),
            "mode": raw_data.get("scan_mode", "mock"),
            "resources_scanned": {
                "s3_buckets": len(raw_data.get("s3_buckets", [])),
                "iam_policies": len(raw_data.get("iam_policies", [])),
                "security_groups": len(raw_data.get("security_groups", []))
            }
        },
        "overall": overall,
        "findings": [
            {
                "resource_type": f.resource_type,
                "resource_name": f.resource_name,
                "resource_id": f.resource_id,
                "issue_type": f.issue_type,
                "issue_title": f.issue_title,
                "description": f.description,
                "risk_score": f.risk_score,
                "risk_label": f.risk_label,
                "score_breakdown": {
                    "exposure": f.exposure_score,
                    "permission": f.permission_score,
                    "impact": f.impact_score
                },
                "threat": {
                    "attack_type": f.attack_type,
                    "mitre_tactic": f.mitre_tactic,
                    "mitre_technique": f.mitre_technique,
                    "real_world_example": f.real_world_example
                },
                "remediation": {
                    "priority": f.remediation_priority,
                    "steps": f.remediation_steps
                },
                "affected_chain_ids": f.affected_chain_ids
            }
            for f in all_findings
        ],
        "attack_chains": active_chains
    }
