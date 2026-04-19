# CloudGuard — Intelligent Cloud Misconfiguration Detection System

## Hackathon Prototype | AWS Security | Threat Intelligence

---

## Quick Start (2 minutes)

### Option A: Frontend Only (Zero Setup)
Just open `frontend/dashboard.html` in any browser. Click "Scan AWS". Done.

### Option B: With FastAPI Backend

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the backend
cd backend
python main.py
# → Runs on http://localhost:8000

# 3. Open the dashboard
open frontend/dashboard.html
# (or serve it: python -m http.server 8080 --directory frontend)
```

### Option C: Live AWS Scan
```bash
# Configure AWS credentials
aws configure
# OR
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Hit the live scan endpoint
curl http://localhost:8000/api/scan?mock=false
```

---

## Project Structure

```
cloud-threat-detector/
├── backend/
│   ├── main.py          # FastAPI server
│   ├── scanner.py       # AWS resource scanner (boto3 + mock)
│   └── analyzer.py      # Risk engine + threat mapping + attack chains
├── frontend/
│   └── dashboard.html   # Complete self-contained UI dashboard
├── data/
│   └── mock_aws_data.json  # Realistic mock AWS environment
├── requirements.txt
└── README.md
```

---

## Architecture

```
AWS Resources ──→ Scanner (boto3/mock)
                        │
                        ▼
               Analyzer Engine
               ├── Rule Engine (misconfig detection)
               ├── Risk Scorer (dynamic 0-100)
               │    └── Score = (Exposure × 0.35) + (Permission × 0.35) + (Impact × 0.30)
               ├── Threat Mapper (MITRE ATT&CK)
               └── Attack Chain Correlator
                        │
                        ▼
               FastAPI REST API
                        │
                        ▼
               HTML Dashboard (Scan → Findings → Chains → Remediation)
```

---

## Features Implemented

### 1. AWS Scanner
| Resource | Checks |
|---|---|
| S3 Buckets | Public access, encryption, versioning, ACL |
| IAM Policies | Wildcard actions (`*`), wildcard resources (`*`), S3 wildcards |
| EC2 Security Groups | Open ports to 0.0.0.0/0 (SSH, RDP, MySQL, PostgreSQL, MongoDB) |

### 2. Dynamic Risk Scoring
Formula: `Score = (Exposure × 0.35) + (Permission × 0.35) + (Impact × 0.30)`

| Factor | What it measures |
|---|---|
| Exposure | Internet accessibility, attachment count |
| Permission | Scope of access granted |
| Impact | Data volume, instance count, sensitivity |

Scores: 0–39 = LOW, 40–64 = MEDIUM, 65–84 = HIGH, 85–100 = CRITICAL

### 3. Threat Mapping (MITRE ATT&CK)
| Misconfiguration | Attack Type | MITRE Technique |
|---|---|---|
| Public S3 | Data Exfiltration | T1530 |
| IAM Wildcard | Privilege Escalation | T1078, T1098 |
| Open SSH | Brute Force | T1110 |
| Open RDP | RDP Exploitation | T1021.001 |
| Open DB Port | Database Compromise | T1190 |

### 4. Attack Chains
- **Chain 1**: SSH Access → EC2 Compromise → IAM Escalation → S3 Exfiltration → Account Takeover
- **Chain 2**: Exposed DB Port → Credential Attack → Ransomware/Data Destruction

### 5. Dashboard
- Security score meter (0-100) with grade
- Severity distribution chart
- Interactive findings table with expandable details
- Attack chain visualization
- Per-finding remediation playbooks with MITRE mapping

---

## API Endpoints

```
GET /                   # Health check
GET /api/scan           # Run scan (mock=true/false)
GET /api/health         # Backend status
```

---

## Demo Script (3 minutes)

### Opening (30 seconds)
"Every day, thousands of AWS environments are misconfigured—not by malicious actors, but by developers moving fast. Capital One lost $190M because of a single S3 misconfiguration. We built CloudGuard to catch these before attackers do."

### Demo (2 minutes)
1. Open `dashboard.html` → Show the clean welcome screen
2. Click **Scan AWS** → Let the terminal-style scan animation play
   - "Notice we're scanning S3, IAM, and Security Groups in parallel"
3. Show the **Security Score: 15.3 / F** at the top
   - "Our dynamic risk engine found 12 findings—8 critical"
4. Point to **Attack Chains**:
   - "Here's the killer feature—we don't just find issues, we chain them. An attacker can start with this exposed SSH port, pivot to EC2, exploit this wildcard IAM policy, and exfiltrate 245GB of customer data. That's a $8.5M breach, step by step."
5. Click any finding → Show **expanded details**:
   - Score breakdown (Exposure / Permission / Impact)
   - MITRE technique mapping
   - Real-world breach reference
   - Step-by-step remediation

### Closing (30 seconds)
"What makes CloudGuard different: not static severity labels, but a dynamic risk formula that accounts for exposure surface, permission scope, and blast radius. Every finding maps to a real MITRE technique and links to real-world breaches. This runs against live AWS in minutes with zero infrastructure—just Python and boto3."

---

## Extending the System

### Add a new check
In `analyzer.py`, add to the appropriate `analyze_*` function:
```python
if some_condition:
    findings.append(Finding(
        issue_type="NEW_CHECK",
        threat_key="new_threat",
        ...
    ))
```

### Add a new threat
In `THREAT_MAP`:
```python
"new_threat": {
    "attack_type": "...",
    "mitre_tactic": "TA0XXX - ...",
    "mitre_technique": "TXXXX - ...",
    ...
}
```

---

## Tech Stack
- **Backend**: Python 3.11+, FastAPI, boto3
- **Frontend**: Vanilla HTML/CSS/JS (zero dependencies, zero build step)
- **Data**: JSON mock + live AWS via boto3
- **Design**: Custom dark terminal aesthetic with JetBrains Mono + Syne fonts
