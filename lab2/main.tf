############################################################
# IAM Attack Path Analyzer - demo lab v2
# Every scenario has a number (S1, S2, ...) used in the demo script.
# SAFETY: this file creates NO access keys and NO login profiles,
# so nobody can actually sign in as these users. Do not add any.
# Destroy the lab after the demo: terraform destroy
############################################################

terraform {
  required_version = ">= 1.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.92"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Project = "iam-attack-path-lab"
    }
  }
}

variable "name_prefix" {
  type    = string
  default = "iamlab"
}

# Rhino-style escalation techniques that Session 10 will detect (S10)
variable "include_technique_cases" {
  type    = bool
  default = true
}

# Cases that show what the tool does NOT evaluate yet (S11)
variable "include_limitation_cases" {
  type    = bool
  default = true
}

# Optional cross-account trust (S9). Use ONLY a second account you own.
# Leave empty to skip. Never put someone else's account id here.
variable "external_account_id" {
  type    = string
  default = ""
  validation {
    condition     = var.external_account_id == "" || can(regex("^[0-9]{12}$", var.external_account_id))
    error_message = "external_account_id must be empty or a 12-digit AWS account id."
  }
}

data "aws_caller_identity" "current" {}

locals {
  p    = var.name_prefix
  acct = data.aws_caller_identity.current.account_id
  pv   = "2012-10-17"
  root = "arn:aws:iam::${local.acct}:root"
}

############################################################
# USERS
############################################################
locals {
  base_users       = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
  technique_users  = var.include_technique_cases ? ["ivan", "judy", "mallory", "niaj"] : []
  limitation_users = var.include_limitation_cases ? ["trent", "ursula"] : []
}

resource "aws_iam_user" "u" {
  for_each = toset(concat(local.base_users, local.technique_users, local.limitation_users))
  name     = "${local.p}-${each.key}"
}

############################################################
# GROUPS
############################################################
resource "aws_iam_group" "g" {
  for_each = toset(["devs", "admins", "auditors"])
  name     = "${local.p}-${each.key}"
}

locals {
  memberships = {
    erin  = ["devs"]     # S5: permission inherited through a group
    heidi = ["auditors"] # S8: group exists, but no escalation path
  }
}

resource "aws_iam_user_group_membership" "m" {
  for_each = local.memberships
  user     = aws_iam_user.u[each.key].name
  groups   = [for g in each.value : aws_iam_group.g[g].name]
}

############################################################
# ROLES
############################################################

# S1: direct trust, one hop (trust names alice's exact ARN)
resource "aws_iam_role" "dev" {
  name = "${local.p}-dev-role"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.u["alice"].arn }
    }]
  })
}

# S2: four-hop chain  alice -> chain-1 -> chain-2 -> chain-3 -> prod-admin
resource "aws_iam_role" "chain_1" {
  name = "${local.p}-chain-1"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.u["alice"].arn }
    }]
  })
}

resource "aws_iam_role" "chain_2" {
  name = "${local.p}-chain-2"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_role.chain_1.arn }
    }]
  })
}

resource "aws_iam_role" "chain_3" {
  name = "${local.p}-chain-3"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_role.chain_2.arn }
    }]
  })
}

# S3: diamond  bob -> diamond-a / diamond-b -> diamond-merge -> prod-admin
# Two equally short routes, so removing only one edge does not fix it.
resource "aws_iam_role" "diamond_a" {
  name = "${local.p}-diamond-a"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.u["bob"].arn }
    }]
  })
}

resource "aws_iam_role" "diamond_b" {
  name = "${local.p}-diamond-b"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.u["bob"].arn }
    }]
  })
}

resource "aws_iam_role" "diamond_merge" {
  name = "${local.p}-diamond-merge"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = [aws_iam_role.diamond_a.arn, aws_iam_role.diamond_b.arn] }
    }]
  })
}

# S4: the privileged target (* on *). Reached by chain-3, diamond-merge
# and grace (a 1-hop misconfiguration).
resource "aws_iam_role" "prod_admin" {
  name = "${local.p}-prod-admin"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        AWS = [
          aws_iam_role.chain_3.arn,
          aws_iam_role.diamond_merge.arn,
          aws_iam_user.u["grace"].arn,
        ]
      }
    }]
  })
}

# S5/S6: trust names the account root -> caller ALSO needs sts:AssumeRole
resource "aws_iam_role" "deploy" {
  name = "${local.p}-deploy-role"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = local.root }
    }]
  })
}

# S6: wildcard resource (role/iamlab-tools-*) matches both roles below
resource "aws_iam_role" "tools_a" {
  name = "${local.p}-tools-a"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = local.root }
    }]
  })
}

resource "aws_iam_role" "tools_b" {
  name = "${local.p}-tools-b"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = local.root }
    }]
  })
}

# S12: trust "*" guarded by a condition. The tool ignores Conditions, so it
# treats this like account-level trust. The condition keeps it safe in reality.
resource "aws_iam_role" "guarded" {
  name = "${local.p}-guarded-role"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "*" }
      Condition = { StringEquals = { "aws:PrincipalAccount" = local.acct } }
    }]
  })
}

# S7: service roles are never attack nodes (shown as Service nodes)
resource "aws_iam_role" "ec2" {
  name = "${local.p}-ec2-role"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role" "lambda" {
  name = "${local.p}-lambda-role"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${local.p}-ec2-profile"
  role = aws_iam_role.ec2.name
}

# S9: optional cross-account trust (External node, never an attack node)
resource "aws_iam_role" "partner" {
  count = var.external_account_id == "" ? 0 : 1
  name  = "${local.p}-partner-role"
  assume_role_policy = jsonencode({
    Version = local.pv
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${var.external_account_id}:root" }
    }]
  })
}

############################################################
# MANAGED POLICIES
############################################################
locals {
  core_policies = tomap({
    readonly_s3 = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = ["s3:GetObject", "s3:ListBucket"], Resource = "arn:aws:s3:::*" }]
    })
    ec2_describe = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = ["ec2:Describe*"], Resource = "*" }]
    })
    lambda_logs = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "*" }]
    })
    deploy_perms = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = ["s3:PutObject"], Resource = "arn:aws:s3:::*" }]
    })
    # The privileged policy: * on *
    admin_all = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
    })
    audit_readonly = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = ["iam:Get*", "iam:List*"], Resource = "*" }]
    })
    # S5: carol has permission for root-trust role and the guarded role
    carol_assume = jsonencode({
      Version = local.pv
      Statement = [{
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = [aws_iam_role.deploy.arn, aws_iam_role.guarded.arn]
      }]
    })
    # S5: group-level permission (inherited by erin)
    devs_assume_deploy = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.deploy.arn }]
    })
    # S8: permission WITHOUT trust: dev-role trusts only alice -> no edge for dave
    dave_assume_dev = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.dev.arn }]
    })
    # S6: wildcard resource
    frank_assume_tools = jsonencode({
      Version = local.pv
      Statement = [{
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::${local.acct}:role/${local.p}-tools-*"
      }]
    })
    # S8: a ROLE with permission but no trust: prod-admin does not trust tools-b
    tools_b_assume_admin = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.prod_admin.arn }]
    })
  })

  # S10: privilege-escalation techniques (detected in Session 10, not yet)
  technique_policies = tomap({
    ivan_add_to_group = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = "iam:AddUserToGroup", Resource = aws_iam_group.g["admins"].arn }]
    })
    judy_update_trust = jsonencode({
      Version = local.pv
      Statement = [
        { Effect = "Allow", Action = "iam:UpdateAssumeRolePolicy", Resource = aws_iam_role.prod_admin.arn },
        { Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.prod_admin.arn },
      ]
    })
    mallory_put_role_policy = jsonencode({
      Version = local.pv
      Statement = [
        { Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.deploy.arn },
        { Effect = "Allow", Action = "iam:PutRolePolicy", Resource = aws_iam_role.deploy.arn },
      ]
    })
    # policy edits ITSELF (ARN built from the name, so no self-reference cycle)
    niaj_self_edit = jsonencode({
      Version = local.pv
      Statement = [{
        Effect   = "Allow"
        Action   = "iam:CreatePolicyVersion"
        Resource = "arn:aws:iam::${local.acct}:policy/${local.p}-niaj-self-edit"
      }]
    })
  })

  # S11: known limitations (Deny is not evaluated yet)
  limitation_policies = tomap({
    trent_allow_deploy = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.deploy.arn }]
    })
    trent_deny_deploy = jsonencode({
      Version = local.pv
      Statement = [{ Effect = "Deny", Action = "sts:AssumeRole", Resource = aws_iam_role.deploy.arn }]
    })
  })

  all_policies = merge(
    local.core_policies,
    var.include_technique_cases ? local.technique_policies : tomap({}),
    var.include_limitation_cases ? local.limitation_policies : tomap({}),
  )
}

resource "aws_iam_policy" "p" {
  for_each    = local.all_policies
  name        = "${local.p}-${replace(each.key, "_", "-")}"
  description = "IAM attack path lab policy"
  policy      = each.value
}

# S11: inline policy: the tool does not read inline policies yet
resource "aws_iam_user_policy" "ursula_inline" {
  for_each = var.include_limitation_cases ? toset(["ursula"]) : toset([])
  name     = "${local.p}-ursula-inline-assume-deploy"
  user     = aws_iam_user.u[each.key].name
  policy = jsonencode({
    Version = local.pv
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.deploy.arn }]
  })
}

############################################################
# ATTACHMENTS
############################################################
locals {
  role_names = {
    dev           = aws_iam_role.dev.name
    chain_1       = aws_iam_role.chain_1.name
    chain_2       = aws_iam_role.chain_2.name
    chain_3       = aws_iam_role.chain_3.name
    diamond_a     = aws_iam_role.diamond_a.name
    diamond_b     = aws_iam_role.diamond_b.name
    diamond_merge = aws_iam_role.diamond_merge.name
    prod_admin    = aws_iam_role.prod_admin.name
    deploy        = aws_iam_role.deploy.name
    tools_a       = aws_iam_role.tools_a.name
    tools_b       = aws_iam_role.tools_b.name
    guarded       = aws_iam_role.guarded.name
    ec2           = aws_iam_role.ec2.name
    lambda        = aws_iam_role.lambda.name
  }

  role_attachments = [
    { role = "dev", policy = "readonly_s3" },
    { role = "chain_1", policy = "ec2_describe" },
    { role = "chain_2", policy = "ec2_describe" },
    { role = "chain_3", policy = "ec2_describe" },
    { role = "diamond_a", policy = "ec2_describe" },
    { role = "diamond_b", policy = "ec2_describe" },
    { role = "diamond_merge", policy = "ec2_describe" },
    { role = "prod_admin", policy = "admin_all" },
    { role = "deploy", policy = "deploy_perms" },
    { role = "tools_a", policy = "readonly_s3" },
    { role = "tools_b", policy = "tools_b_assume_admin" },
    { role = "guarded", policy = "readonly_s3" },
    { role = "ec2", policy = "ec2_describe" },
    { role = "lambda", policy = "lambda_logs" },
  ]

  user_attachments = concat(
    [
      { user = "carol", policy = "carol_assume" },
      { user = "dave", policy = "dave_assume_dev" },
      { user = "frank", policy = "frank_assume_tools" },
    ],
    var.include_technique_cases ? [
      { user = "ivan", policy = "ivan_add_to_group" },
      { user = "judy", policy = "judy_update_trust" },
      { user = "mallory", policy = "mallory_put_role_policy" },
      { user = "niaj", policy = "niaj_self_edit" },
    ] : [],
    var.include_limitation_cases ? [
      { user = "trent", policy = "trent_allow_deploy" },
      { user = "trent", policy = "trent_deny_deploy" },
    ] : [],
  )

  group_attachments = {
    devs     = "devs_assume_deploy"
    admins   = "admin_all"
    auditors = "audit_readonly"
  }
}

resource "aws_iam_role_policy_attachment" "r" {
  for_each   = { for a in local.role_attachments : "${a.role}.${a.policy}" => a }
  role       = local.role_names[each.value.role]
  policy_arn = aws_iam_policy.p[each.value.policy].arn
}

resource "aws_iam_user_policy_attachment" "u" {
  for_each   = { for a in local.user_attachments : "${a.user}.${a.policy}" => a }
  user       = aws_iam_user.u[each.value.user].name
  policy_arn = aws_iam_policy.p[each.value.policy].arn
}

resource "aws_iam_group_policy_attachment" "g" {
  for_each   = local.group_attachments
  group      = aws_iam_group.g[each.key].name
  policy_arn = aws_iam_policy.p[each.value].arn
}

resource "aws_iam_role_policy_attachment" "partner" {
  count      = var.external_account_id == "" ? 0 : 1
  role       = aws_iam_role.partner[0].name
  policy_arn = aws_iam_policy.p["readonly_s3"].arn
}

############################################################
# OUTPUT: expected results to check the tool against
############################################################
output "scan_command" {
  value = "python src/collect.py --profile default --region us-east-1 --prefix ${var.name_prefix} --out snapshots/lab2.json"
}