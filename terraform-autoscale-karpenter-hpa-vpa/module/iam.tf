resource "aws_iam_role" "ec2_role" {
  name = "EC2Role-for-BankApp"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

}

resource "aws_iam_policy" "policy" {
  name        = "bankapp-policy-EC2"
  path        = "/"
  description = "My test policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "s3:ListAllMyBuckets",
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:BatchCompleteUpload",
          "ecr:UploadImage",
          "ecr:CreateRepository",
          "ecr:DescribeRepositories",
          "ecr:DescribeImages",
          "ecr:GetRepositoryPolicy",
          "ecr:ListTagsForResource",
          "ecr:DescribeImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:ListImages",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerChunk",
          "ecr:BatchGetImage",
          "ecr:PullImage"
        ]
        Effect   = "Allow"
        "Resource": "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_role_policy_attachment_loggroup_s3_ecr" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_role_policy_attachment" "ec2_role_policy_attachment_cloudwatchagentserverpolicy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "ec2_role_policy_attachment_awsssmmanagedinstancecore" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "BANKAPP-IAM-INSTANCE-PROFILE"
  role = "${aws_iam_role.ec2_role.name}"
}
