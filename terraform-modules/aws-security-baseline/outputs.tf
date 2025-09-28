# Outputs for AWS Security Baseline Module

# CloudTrail Outputs
output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = var.enable_cloudtrail ? aws_cloudtrail.security_audit[0].arn : null
}

output "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  value       = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail_logs[0].bucket : null
}

output "cloudtrail_kms_key_id" {
  description = "KMS key ID used for CloudTrail encryption"
  value       = var.enable_cloudtrail ? aws_kms_key.cloudtrail[0].id : null
}

output "cloudtrail_log_group_arn" {
  description = "ARN of the CloudWatch log group for CloudTrail"
  value       = var.enable_cloudtrail ? aws_cloudwatch_log_group.cloudtrail[0].arn : null
}

# AWS Config Outputs
output "config_recorder_name" {
  description = "Name of the AWS Config configuration recorder"
  value       = var.enable_config ? aws_config_configuration_recorder.security[0].name : null
}

output "config_bucket_name" {
  description = "Name of the S3 bucket for AWS Config"
  value       = var.enable_config ? aws_s3_bucket.config[0].bucket : null
}

output "config_role_arn" {
  description = "ARN of the IAM role for AWS Config"
  value       = var.enable_config ? aws_iam_role.config[0].arn : null
}

output "config_rules" {
  description = "List of AWS Config rules created"
  value = var.enable_config ? [
    aws_config_config_rule.root_access_key_check[0].name,
    aws_config_config_rule.iam_password_policy[0].name,
    aws_config_config_rule.mfa_enabled_for_root[0].name,
    aws_config_config_rule.s3_bucket_public_access_prohibited[0].name,
    aws_config_config_rule.encrypted_volumes[0].name
  ] : []
}

# GuardDuty Outputs
output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = var.enable_guardduty ? aws_guardduty_detector.security[0].id : null
}

output "guardduty_detector_arn" {
  description = "ARN of the GuardDuty detector"
  value       = var.enable_guardduty ? aws_guardduty_detector.security[0].arn : null
}

# Security Hub Outputs
output "security_hub_arn" {
  description = "ARN of the Security Hub account"
  value       = var.enable_security_hub ? aws_securityhub_account.security[0].arn : null
}

output "security_hub_standards" {
  description = "List of Security Hub standards enabled"
  value = var.enable_security_hub ? [
    aws_securityhub_standards_subscription.aws_foundational[0].standards_arn,
    aws_securityhub_standards_subscription.cis[0].standards_arn
  ] : []
}

# SNS Outputs
output "security_alerts_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = var.enable_sns_alerts ? aws_sns_topic.security_alerts[0].arn : null
}

output "security_alerts_topic_name" {
  description = "Name of the SNS topic for security alerts"
  value       = var.enable_sns_alerts ? aws_sns_topic.security_alerts[0].name : null
}

# KMS Outputs
output "kms_keys" {
  description = "Map of KMS key IDs created by this module"
  value = {
    cloudtrail = var.enable_cloudtrail ? aws_kms_key.cloudtrail[0].id : null
    config     = var.enable_config ? aws_kms_key.config[0].id : null
    sns        = var.enable_sns_alerts ? aws_kms_key.sns[0].id : null
  }
}

output "kms_key_aliases" {
  description = "Map of KMS key aliases created by this module"
  value = {
    cloudtrail = var.enable_cloudtrail ? aws_kms_alias.cloudtrail[0].name : null
    config     = var.enable_config ? aws_kms_alias.config[0].name : null
    sns        = var.enable_sns_alerts ? aws_kms_alias.sns[0].name : null
  }
}

# CloudWatch Outputs
output "cloudwatch_alarms" {
  description = "List of CloudWatch alarm names created"
  value = var.enable_cloudwatch_alarms ? [
    aws_cloudwatch_metric_alarm.unauthorized_api_calls[0].alarm_name,
    aws_cloudwatch_metric_alarm.console_without_mfa[0].alarm_name,
    aws_cloudwatch_metric_alarm.root_usage[0].alarm_name
  ] : []
}

# Security Baseline Summary
output "security_baseline_summary" {
  description = "Summary of security baseline configuration"
  value = {
    account_id           = data.aws_caller_identity.current.account_id
    region               = data.aws_region.current.name
    environment          = var.environment
    cloudtrail_enabled   = var.enable_cloudtrail
    config_enabled       = var.enable_config
    guardduty_enabled    = var.enable_guardduty
    security_hub_enabled = var.enable_security_hub
    sns_alerts_enabled   = var.enable_sns_alerts
    cloudwatch_alarms_enabled = var.enable_cloudwatch_alarms
    compliance_frameworks = var.compliance_frameworks
    created_timestamp    = timestamp()
  }
}

# Compliance Status
output "compliance_status" {
  description = "Compliance status for various frameworks"
  value = {
    cis_benchmark = {
      enabled = var.enable_config && contains(var.compliance_frameworks, "CIS")
      rules = var.enable_config ? [
        "root-access-key-check",
        "iam-password-policy",
        "mfa-enabled-for-root",
        "s3-bucket-public-access-prohibited",
        "encrypted-volumes"
      ] : []
    }
    aws_foundational = {
      enabled = var.enable_security_hub && contains(var.compliance_frameworks, "AWS_FOUNDATIONAL")
      standards_arn = var.enable_security_hub ? aws_securityhub_standards_subscription.aws_foundational[0].standards_arn : null
    }
    pci_dss = {
      enabled = contains(var.compliance_frameworks, "PCI_DSS")
      encryption_at_rest = var.default_encryption
      audit_logging = var.enable_cloudtrail
    }
    soc2 = {
      enabled = contains(var.compliance_frameworks, "SOC2")
      access_controls = var.enforce_mfa
      monitoring = var.enable_guardduty && var.enable_security_hub
      data_protection = var.default_encryption
    }
  }
}

# Security Monitoring URLs
output "security_monitoring_urls" {
  description = "URLs for accessing security monitoring dashboards"
  value = {
    cloudtrail_events = var.enable_cloudtrail ? "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudtrail/home?region=${data.aws_region.current.name}#/events" : null
    guardduty_findings = var.enable_guardduty ? "https://${data.aws_region.current.name}.console.aws.amazon.com/guardduty/home?region=${data.aws_region.current.name}#/findings" : null
    security_hub_findings = var.enable_security_hub ? "https://${data.aws_region.current.name}.console.aws.amazon.com/securityhub/home?region=${data.aws_region.current.name}#/findings" : null
    config_compliance = var.enable_config ? "https://${data.aws_region.current.name}.console.aws.amazon.com/config/home?region=${data.aws_region.current.name}#/compliance/home" : null
  }
}

# Cost Estimation
output "estimated_monthly_cost" {
  description = "Estimated monthly cost breakdown for security services (USD)"
  value = {
    cloudtrail = var.enable_cloudtrail ? {
      data_events = "~$2.00 per 100,000 events"
      management_events = "Free for first trail"
      s3_storage = "~$0.023 per GB/month"
    } : null

    config = var.enable_config ? {
      configuration_items = "~$0.003 per configuration item"
      rules_evaluations = "~$0.001 per evaluation"
    } : null

    guardduty = var.enable_guardduty ? {
      vpc_flow_logs = "~$4.00 per GB analyzed"
      dns_logs = "~$4.00 per GB analyzed"
      s3_data_events = "~$5.00 per million events"
    } : null

    security_hub = var.enable_security_hub ? {
      findings_ingestion = "~$0.0030 per 10,000 findings"
      compliance_checks = "~$0.0010 per check"
    } : null

    kms = "~$1.00 per key per month + usage charges"
    sns = var.enable_sns_alerts ? "~$0.50 per million notifications" : null

    total_estimated_range = "~$50-500 per month (depending on usage)"
  }
}

# Security Team Contacts
output "security_contacts" {
  description = "Security team contact information"
  value = {
    primary_email = var.security_contacts.primary_email
    escalation_email = var.security_contacts.escalation_email
    phone_number = var.security_contacts.phone_number
  }
  sensitive = false
}

# Integration Endpoints
output "integration_endpoints" {
  description = "Endpoints for external integrations"
  value = {
    sns_topic_arn = var.enable_sns_alerts ? aws_sns_topic.security_alerts[0].arn : null
    cloudwatch_log_groups = var.enable_cloudtrail ? [aws_cloudwatch_log_group.cloudtrail[0].name] : []
    s3_buckets = compact([
      var.enable_cloudtrail ? aws_s3_bucket.cloudtrail_logs[0].bucket : "",
      var.enable_config ? aws_s3_bucket.config[0].bucket : ""
    ])
  }
}

# Terraform State Information
output "terraform_state_info" {
  description = "Information about the Terraform state and module"
  value = {
    module_version = "1.0.0"
    terraform_version = "~> 1.0"
    aws_provider_version = "~> 5.0"
    last_applied = timestamp()
    resource_count = {
      cloudtrail_resources = var.enable_cloudtrail ? 8 : 0
      config_resources = var.enable_config ? 12 : 0
      guardduty_resources = var.enable_guardduty ? 1 : 0
      security_hub_resources = var.enable_security_hub ? 3 : 0
      sns_resources = var.enable_sns_alerts ? 4 : 0
      kms_resources = (var.enable_cloudtrail ? 2 : 0) + (var.enable_config ? 2 : 0) + (var.enable_sns_alerts ? 2 : 0)
      cloudwatch_resources = var.enable_cloudwatch_alarms ? 3 : 0
    }
  }
}

# Security Recommendations
output "security_recommendations" {
  description = "Security recommendations based on current configuration"
  value = {
    immediate_actions = compact([
      !var.enable_cloudtrail ? "Enable CloudTrail for API audit logging" : "",
      !var.enable_config ? "Enable AWS Config for compliance monitoring" : "",
      !var.enable_guardduty ? "Enable GuardDuty for threat detection" : "",
      !var.enable_security_hub ? "Enable Security Hub for centralized findings" : "",
      !var.enforce_mfa ? "Enforce MFA for all IAM users" : "",
      !var.default_encryption ? "Enable default encryption for all services" : ""
    ])

    recommended_enhancements = [
      "Configure custom Config rules for organization-specific compliance",
      "Set up automated remediation for common security findings",
      "Implement cross-region backup for critical security data",
      "Configure threat intelligence feeds for enhanced detection",
      "Set up SIEM integration for centralized log analysis",
      "Implement automated penetration testing schedule"
    ]

    cost_optimization = [
      "Review CloudTrail data event logging scope to optimize costs",
      "Configure Config rule evaluation frequency based on criticality",
      "Set up lifecycle policies for long-term log retention",
      "Consider reserved capacity for high-volume services"
    ]
  }
}