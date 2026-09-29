terraform{
    required_providers{
        aws = {
            source = "hashicorp/aws"
            version = "~> 5.92"
        }
    }
    required_version = ">=1.2"
}
provider "aws"{
    region = "us-east-1"
}

resource "aws_iam_user" "tu"{
    name = "testuser"
    
}

resource "aws_iam_group" "tg"{
    name = "testgroup"
}

resource "aws_iam_role" "tr"{
    name = "testrole"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Sid = ""
                Principal = {
                    AWS = aws_iam_user.tu.arn
                }
            },
        ]
    })
}
resource "aws_iam_role" "tr2"{
    name = "testrole2"
    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Sid = ""
                Principal = {
                    Service = "ec2.amazonaws.com"
                }
            },
        ]
    })
}
resource "aws_iam_policy" "tp" {
    name = "testpolicy"
    description = "Test policy for aws minor project"
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = [
                    "ec2:Describe*"
                ]
                Effect = "Allow"
                Resource = "*"
            },
        ]
    })
}
resource "aws_iam_policy" "tp2"{
    name = "testpolicy2"
    description = "2nd test policy for aws minor project"
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = [
                    "s3:GetObject",
                    "s3:ListBucket"
                ]
                Effect = "Allow"
                Resource = "arn:aws:s3:::*"
            },
        ]
    })
}
resource "aws_iam_instance_profile" "tip"{
    name = "testprofile"
    role = aws_iam_role.tr2.name
}

resource "aws_iam_user_group_membership" "tutotg"{
    user = aws_iam_user.tu.name
    groups = [
        aws_iam_group.tg.name,
    ]
}

resource "aws_iam_group_policy_attachment" "tp2totg"{
    policy_arn  = aws_iam_policy.tp2.arn
    group = aws_iam_group.tg.name
}

resource "aws_iam_role_policy_attachment" "tptotr2"{
    role = aws_iam_role.tr2.name
    policy_arn = aws_iam_policy.tp.arn
}
resource "aws_iam_role_policy_attachment" "tptotr"{
    role = aws_iam_role.tr.name
    policy_arn = aws_iam_policy.tp.arn
}

resource "aws_iam_user" "tu2" {
    name = "testuser2"
}
resource "aws_iam_role" "tr3"{
    name = "testrole3"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Sid = ""
                Principal = {
                    AWS = aws_iam_user.tu2.arn
                }
            },
        ]
    })
}
resource "aws_iam_role" "tr4"{
    name = "testrole4"
    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Sid = ""
                Principal = {
                    AWS = aws_iam_user.tu2.arn
                }
            },
        ]
    })
}
resource "aws_iam_role" "tr5"{
    name = "testrole5"
    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Sid = ""
                Principal = {
                    AWS = [aws_iam_role.tr3.arn,aws_iam_role.tr4.arn]
                }
            },
        ]
    })
}

resource "aws_iam_role_policy_attachment" "tp2totr5"{
    role = aws_iam_role.tr5.name
    policy_arn = aws_iam_policy.tp2.arn
}