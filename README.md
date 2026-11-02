# AWS IAM Attack Path Analyzer

Graph-Based Privilege Escalation & Security Baseline Validation

> **LIMITATION NOTICE:**
> Plausible access paths under a simplified IAM model. Explicit Deny, Conditions, permission boundaries, and SCPs are not evaluated.

A Python-based AWS IAM security analysis platform that identifies privilege escalation paths and validates IAM configuration against an organization-defined security baseline.

---

## Features

- **Automated Collection:** Extracts IAM users, groups, roles, customer-managed policies, and assume-role trust relationships into self-contained JSON snapshots.
- **Offline Graph Analysis:** Constructs directed multi-graphs of IAM relationships (`member-of`, `attached-policy`, `trusted-to-assume`, and evaluated `can-assume` escalation edges) without making live AWS API calls during analysis.
- **Attack Path Reachability:** Calculates shortest escalation paths from any principal to accessible target roles, supporting maximum-hop cutoffs and cycle detection.
- **Interactive Web Interface:** Local FastAPI server and standalone frontend running vis-network graph visualization with identity exploration and path highlighting.

---

## Installation

```powershell
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

---

## Quickstart (Sample Lab)

The repository includes an offline sample snapshot (`snapshots/sample_lab.json`) modeling a representative lab environment with 2 users, 1 group, 5 roles, and 3 policies.

```powershell
# Start local API server and UI (binds only to 127.0.0.1)
uvicorn api:app --app-dir src --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your web browser. The sample snapshot loads automatically.

---

## Collecting from Your AWS Account

To scan your own AWS account:

```powershell
# Scan with default "test" prefix filter
python src/collect.py --profile my-profile --region us-east-1 --prefix test --out snapshots/mine.json

# Scan entire account (no prefix filtering)
python src/collect.py --profile my-profile --region us-east-1 --prefix "" --out snapshots/full_account.json
```

### Minimal Read-Only IAM Collector Permissions

Attach the following read-only policy to the scanning identity:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadOnlyCollection",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListGroups",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:ListUserPolicies",
        "iam:ListGroupPolicies",
        "iam:ListRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListGroupsForUser",
        "iam:ListInstanceProfiles",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Security Notes

- **Localhost Only:** The web interface binds strictly to `127.0.0.1`. No external authentication or open network listener is enabled.
- **Secret Hygiene:** Snapshots store IAM structure and may include account IDs or resource ARNs. All snapshot files under `snapshots/` are ignored by `.gitignore` (except the sanitized `snapshots/sample_lab.json`). Never commit real account snapshots to version control.

---

## Project Layout

```text
├── src/
│   ├── api.py                  # FastAPI application & REST endpoints
│   ├── analysis.py             # Attack graph composition & reachability reporting
│   ├── graph_export.py         # JSON serialization for full and attack views
│   ├── graph.py                # MultiDiGraph builder & node classification
│   ├── attack_path.py          # Subgraph attack view & find_reachable algorithm
│   ├── assume_role.py          # Trust and permission evaluation (find_can_assume)
│   ├── effective_permission.py # Policy resolution for users and roles
│   ├── trust_policy_parser.py  # AssumeRolePolicyDocument statement parser
│   ├── policy_parser.py        # IAM policy statement parser
│   ├── policy_matcher.py       # Action and resource wildcard pattern matcher
│   ├── snapshot.py             # Schema v1 serialization and file I/O
│   ├── collect.py              # CLI utility to snapshot an AWS account
│   ├── IAM_Enumerator.py       # Configurable boto3 pagination client
│   └── iam_models.py           # Domain dataclasses
├── frontend/
│   ├── index.html              # Standalone web UI
│   ├── app.js                  # Frontend client (DOM APIs, zero innerHTML)
│   ├── style.css               # Responsive dark theme
│   └── vendor/                 # Offline vis-network library
├── snapshots/
│   └── sample_lab.json         # Sanitized lab snapshot
├── tests/                      # Automated test suite (180+ tests)
└── requirements.txt            # Dependency manifest
```

---

## Running Automated Tests

```powershell
# Run full offline test suite
pytest -m "not aws" -q

# Run with verbose reporting
pytest -m "not aws" -v
```

---

## Roadmap

- **[Planned]** Privilege classification (admin, data access, privilege escalation).
- **[Planned]** Drift detection comparing differences between two snapshots.
- **[Planned]** Risk scoring based on escalation hop counts and blast radius.
- **[Planned]** Automated PDF compliance and audit reports.
