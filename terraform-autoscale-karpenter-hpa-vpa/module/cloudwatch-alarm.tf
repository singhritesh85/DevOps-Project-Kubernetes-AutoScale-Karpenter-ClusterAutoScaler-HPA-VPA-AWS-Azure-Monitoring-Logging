resource "aws_sns_topic" "sns_topic" {
  name = "bankapp-topic"
  display_name = "bankapp-topic"
}

resource "aws_sns_topic_subscription" "sns_topic_subscription" {
  topic_arn = aws_sns_topic.sns_topic.arn
  protocol  = "email"
  endpoint  = "abc@gmail.com"   ### Provide your Group Email ID
}

############################# CloudWatch Alarm for AWS Certificate Manager(ACM) SSL Certificate ########################################################

resource "aws_cloudwatch_metric_alarm" "jenkins_acm_certificate_expiration" {
  alarm_name            = "Jenkins-ACM-Certificate-Expiration-Alert"
  alarm_description     = "Alert when ACM certificate for singhritesh85.com is expiring."
  metric_name          = "NumberOfDaysUntilExpiration"
  namespace             = "AWS/CertificateManager"
  comparison_operator   = "LessThanThreshold"
  threshold             = 30
  evaluation_periods    = 1
  period                = 3600
  statistic            = "Average"
  treat_missing_data = "notBreaching" ### Or other option
  dimensions = {
    CertificateArn = var.certificate_arn 
  }
  alarm_actions = [aws_sns_topic.sns_topic.arn]
  ok_actions    = [aws_sns_topic.sns_topic.arn] # Optional, you can use different OK actions
  actions_enabled = true
}

############################# CPU-Utilization, Memory and Disk-Usage Alarm Jenkins Master #############################################################

resource "aws_cloudwatch_metric_alarm" "jenkins_master_cpu_alarm" {
  alarm_name          = "Jenkins-Master-CPUUtilizationAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120  # 2 minutes
  statistic           = "Average"
  threshold           = 70   # Set your threshold value

  dimensions = {
    InstanceId = aws_instance.jenkins_master.id 
  }

  treat_missing_data = "missing"
  alarm_description = "Alarm when CPU utilization is greater than or equal to 70%"
  actions_enabled = true
  alarm_actions = [aws_sns_topic.sns_topic.arn]
  ok_actions = [aws_sns_topic.sns_topic.arn]

  depends_on = [null_resource.jenkins_master]

}

resource "aws_cloudwatch_metric_alarm" "jenkins_master_disk_usage_alarm" {
  alarm_name          = "Jenkins-Master-DiskUsageAlarm"
  alarm_description   = "Alarm when disk usage on Jenkins Master Server is high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "disk_used_percent"
  namespace           = "CWAgent"
  period              = 120
  statistic           = "Average"
  threshold           = 70
  alarm_actions       = [aws_sns_topic.sns_topic.arn]
  ok_actions         = [aws_sns_topic.sns_topic.arn]
  dimensions = {
    InstanceId = aws_instance.jenkins_master.id
    ###DiskMountPath = "/" # Specify the mount point (e.g., /)
  }
  treat_missing_data = "notBreaching" # Or other option

  depends_on = [null_resource.jenkins_master]
}

resource "aws_cloudwatch_metric_alarm" "jenkins_master_memory_alarm" {
  alarm_name         = "Jenkins_Master_Memory_High_Utilization_Alarm"
  alarm_description  = "Alarm if EC2 memory usage exceeds 70%"
  metric_name        = "mem_used_percent"
  namespace          = "CWAgent"
  statistic          = "Average"
  threshold          = 70
  evaluation_periods = 1
  period             = 120
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.sns_topic.arn] # Replace with your SNS topic ARN
  ok_actions         = [aws_sns_topic.sns_topic.arn]   # Replace with your SNS topic ARN
  treat_missing_data = "notBreaching" # Or other option
  dimensions = {
    InstanceId = aws_instance.jenkins_master.id
  }

  depends_on = [null_resource.jenkins_master]
}

############################# CPU-Utilization, Memory and Disk-Usage Alarm Jenkins Slave #############################################################

resource "aws_cloudwatch_metric_alarm" "jenkins_slave_cpu_alarm" {
  alarm_name          = "Jenkins-Slave-CPUUtilizationAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120  # 2 minutes
  statistic           = "Average"
  threshold           = 70   # Set your threshold value

  dimensions = {
    InstanceId = aws_instance.jenkins_slave.id
  }

  treat_missing_data = "missing"
  alarm_description = "Alarm when CPU utilization is greater than or equal to 70%"
  actions_enabled = true
  alarm_actions = [aws_sns_topic.sns_topic.arn]
  ok_actions = [aws_sns_topic.sns_topic.arn]
 
  depends_on = [null_resource.jenkins_slave]

}

resource "aws_cloudwatch_metric_alarm" "jenkins_slave_disk_usage_alarm" {
  alarm_name          = "Jenkins-Slave-DiskUsageAlarm"
  alarm_description   = "Alarm when disk usage on Jenkins Slave is high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "disk_used_percent"
  namespace           = "CWAgent"
  period              = 120
  statistic           = "Average"
  threshold           = 70
  alarm_actions       = [aws_sns_topic.sns_topic.arn]
  ok_actions         = [aws_sns_topic.sns_topic.arn]
  dimensions = {
    InstanceId = aws_instance.jenkins_slave.id
    ###DiskMountPath = "/" # Specify the mount point (e.g., /)
  }
  treat_missing_data = "missing" # Or other option

  depends_on = [null_resource.jenkins_slave]
}

resource "aws_cloudwatch_metric_alarm" "jenkins_slave_memory_alarm" {
  alarm_name         = "Jenkins_Slave_Memory_High_Utilization_Alarm"
  alarm_description  = "Alarm if EC2 memory usage exceeds 70%"
  metric_name        = "mem_used_percent"
  namespace          = "CWAgent"
  statistic          = "Average"
  threshold          = 70
  evaluation_periods = 1
  period             = 120
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.sns_topic.arn] # Replace with your SNS topic ARN
  ok_actions         = [aws_sns_topic.sns_topic.arn]   # Replace with your SNS topic ARN
  treat_missing_data = "missing" # Or other option
  dimensions = {
    InstanceId = aws_instance.jenkins_slave.id
  }
  
  depends_on = [null_resource.jenkins_slave]
}

############################################################ Cloudwatch Real User Monitoring (RUM) #######################################################    

resource "aws_rum_app_monitor" "bankapp_rum" {
  name   = "bankapp-rum"
  domain = "bankapp.singhritesh85.com"
  cw_log_enabled = true
  app_monitor_configuration {
    allow_cookies = true
    enable_xray = false
    session_sample_rate = "1"
    guest_role_arn = aws_iam_role.bankapp_guest_rum_role.arn 
    identity_pool_id = aws_cognito_identity_pool.bankapp_rum_identity_pool.id
    telemetries = ["errors", "performance", "http"]
  }
  #custom_events {
  #  status = "ENABLED"
  #}

  depends_on = [aws_cloudwatch_metric_alarm.jenkins_master_memory_alarm, aws_cloudwatch_metric_alarm.jenkins_slave_memory_alarm]
}

resource "aws_rum_metrics_destination" "rum_destination" {
  app_monitor_name = aws_rum_app_monitor.bankapp_rum.name
  destination      = "CloudWatch"
}

###################################################### Cognito Identity Pool For Cloudwatch RUM #########################################################

resource "random_id" "rng" {
  keepers = {
    first = "${timestamp()}"
  }     
  byte_length = 6
}

resource "aws_cognito_identity_pool" "bankapp_rum_identity_pool" {
  allow_unauthenticated_identities = true
  identity_pool_name             = "RUM-Monitor-${data.aws_region.current.name}-${data.aws_caller_identity.current.account_id}-${random_id.rng.hex}"   ### Replace with your desired name
  supported_login_providers = {
    provider_name = "cognito"   ### You can add other providers if needed
  }
}

# Create an IAM Role for Guest Users
resource "aws_iam_role" "bankapp_guest_rum_role" {
  name = "bankapp-guest-rum-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        "Federated" = "cognito-identity.amazonaws.com"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
          StringEquals = {
            "cognito-identity.amazonaws.com:aud" = "${aws_cognito_identity_pool.bankapp_rum_identity_pool.id}"
          }
          "ForAnyValue:StringLike" = {
             "cognito-identity.amazonaws.com:amr" = "unauthenticated"
          }
      }
    }] 
  })
}

# Create an IAM Policy for RUM Data Collection
resource "aws_iam_policy" "bankapp_guest_rum_policy" {
  name   = "bankapp-rum-guest-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rum:PutRumEvents"
        ]
        Resource = ["arn:aws:rum:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:appmonitor/${aws_rum_app_monitor.bankapp_rum.name}"]
      }
    ]
  })
}

# Attach the IAM Policy to the Guest Role
resource "aws_iam_role_policy_attachment" "bankapp_guest_rum_policy_attachment" {
  role      = aws_iam_role.bankapp_guest_rum_role.name
  policy_arn = aws_iam_policy.bankapp_guest_rum_policy.arn
}

# Update Cognito Identity Pool with the Guest Role
resource "aws_cognito_identity_pool_roles_attachment" "bankapp_guest_identity_pool_role_attachment" {
  identity_pool_id = aws_cognito_identity_pool.bankapp_rum_identity_pool.id
  roles = {
    unauthenticated = aws_iam_role.bankapp_guest_rum_role.arn
  }
}

######################################################## S3 Bucket to for Canary Artifacts Store #############################################################

resource "aws_s3_bucket" "s3_bucket_synthetic_canary" {
  bucket = "cw-syn-results-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  
  force_destroy = true

  tags = {
    Environment = var.env
  }
}

#S3 Bucket Server Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "s3bucket_encryption_synthetic_canary" {
  bucket = aws_s3_bucket.s3_bucket_synthetic_canary.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

############################################################# Clouwatch Synthetic Canaries ###################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_iam_role" "bankapp_synthetics_canary_role" {
  name               = "bankapp-syntheic-canary-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        "Service" = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}


resource "aws_iam_policy" "bankapp_synthetics_canary_policy" {
  name = "SyntheticsCanaryPolicy"
  description = "IAM policy for CloudWatch Synthetics canaries"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.s3_bucket_synthetic_canary.id}/canary/${data.aws_region.current.name}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "s3:GetBucketLocation"
        ]
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.s3_bucket_synthetic_canary.id}"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:CreateLogGroup"
        ]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/cwsyn-dexter-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "xray:PutTraceSegments"
        ]
        Resource = [
          "*"
        ]
      },
      {
        Effect = "Allow",
        Resource = "*",
        Action = "cloudwatch:PutMetricData"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace": "CloudWatchSynthetics"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bankapp_synthetics_policy_attachment" {
  role       = aws_iam_role.bankapp_synthetics_canary_role.name
  policy_arn = aws_iam_policy.bankapp_synthetics_canary_policy.arn
}

resource "aws_synthetics_canary" "bankapp_synthetic_canary" {
  name                 = "bankapp-synthetic-canary"
  artifact_s3_location = "s3://${aws_s3_bucket.s3_bucket_synthetic_canary.id}"
  execution_role_arn   = aws_iam_role.bankapp_synthetics_canary_role.arn
  handler              = "lambdatest.handler"
  zip_file             = "canary-run/lambdatest.zip"
  runtime_version      = "syn-nodejs-playwright-2.0"
  failure_retention_period = "30"
  success_retention_period = "30"
  artifact_config {
    s3_encryption {
      encryption_mode = "SSE_S3"
    }
  }
  schedule {
    expression = "rate(1 minute)"
  }
  start_canary = false     #true
  delete_lambda = true
}

resource "aws_cloudwatch_metric_alarm" "bankapp_synthetic_canary_alarm" {
  alarm_name                = "synthetic-canary-alarm-for-bankapp-url"
  comparison_operator       = "LessThanThreshold"
  evaluation_periods        = "2"
  metric_name               = "SuccessPercent"
  namespace                 = "CloudWatchSynthetics"
  threshold                 = "100"
  statistic                 = "Average"
  period                    = "300"
  alarm_description         = "This alarm fires if the canary fails"
  treat_missing_data        = "missing"
  alarm_actions             = [aws_sns_topic.sns_topic.arn]

  dimensions = {
    CanaryName = aws_synthetics_canary.bankapp_synthetic_canary.name
  }
}
