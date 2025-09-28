# Variables for AWS Security Baseline Module

variable "name_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "security-baseline"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "Name prefix must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["development", "staging", "production", "sandbox"], var.environment)
    error_message = "Environment must be one of: development, staging, production, sandbox."
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Owner       = "security-team"
    Environment = "production"
    Project     = "security-baseline"
  }
}

# CloudTrail Configuration
variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail for API audit logging"
  type        = bool
  default     = true
}

variable "cloudtrail_log_retention_days" {
  description = "Number of days to retain CloudTrail logs in S3"
  type        = number
  default     = 2555  # 7 years for compliance

  validation {
    condition     = var.cloudtrail_log_retention_days >= 90
    error_message = "CloudTrail log retention must be at least 90 days for compliance."
  }
}

variable "cloudwatch_log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 365

  validation {
    condition     = var.cloudwatch_log_retention_days >= 30
    error_message = "CloudWatch log retention must be at least 30 days."
  }
}

variable "sensitive_bucket_prefix" {
  description = "Prefix for sensitive S3 buckets to monitor in CloudTrail"
  type        = string
  default     = "sensitive"
}

# AWS Config Configuration
variable "enable_config" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = true
}

# GuardDuty Configuration
variable "enable_guardduty" {
  description = "Enable Amazon GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "guardduty_finding_frequency" {
  description = "Frequency of GuardDuty findings publication"
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition = contains([
      "FIFTEEN_MINUTES",
      "ONE_HOUR",
      "SIX_HOURS"
    ], var.guardduty_finding_frequency)
    error_message = "GuardDuty finding frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

# Security Hub Configuration
variable "enable_security_hub" {
  description = "Enable AWS Security Hub for centralized security findings"
  type        = bool
  default     = true
}

# SNS Alerts Configuration
variable "enable_sns_alerts" {
  description = "Enable SNS topic for security alerts"
  type        = bool
  default     = true
}

variable "security_alert_emails" {
  description = "List of email addresses to receive security alerts"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for email in var.security_alert_emails : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All email addresses must be valid."
  }
}

# CloudWatch Alarms Configuration
variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for security monitoring"
  type        = bool
  default     = true
}

# KMS Configuration
variable "kms_deletion_window" {
  description = "Number of days before KMS key deletion (7-30 days)"
  type        = number
  default     = 30

  validation {
    condition     = var.kms_deletion_window >= 7 && var.kms_deletion_window <= 30
    error_message = "KMS deletion window must be between 7 and 30 days."
  }
}

# Compliance Settings
variable "compliance_frameworks" {
  description = "List of compliance frameworks to enable"
  type        = list(string)
  default     = ["CIS", "AWS_FOUNDATIONAL", "PCI_DSS", "SOC2"]

  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains(["CIS", "AWS_FOUNDATIONAL", "PCI_DSS", "SOC2", "HIPAA", "NIST"], framework)
    ])
    error_message = "Compliance frameworks must be from: CIS, AWS_FOUNDATIONAL, PCI_DSS, SOC2, HIPAA, NIST."
  }
}

# Advanced Security Features
variable "enable_macie" {
  description = "Enable Amazon Macie for data classification and protection"
  type        = bool
  default     = false
}

variable "enable_inspector" {
  description = "Enable Amazon Inspector for vulnerability assessments"
  type        = bool
  default     = false
}

variable "enable_waf" {
  description = "Enable AWS WAF for web application protection"
  type        = bool
  default     = false
}

variable "enable_shield_advanced" {
  description = "Enable AWS Shield Advanced for DDoS protection"
  type        = bool
  default     = false
}

# Network Security
variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for network monitoring"
  type        = bool
  default     = true
}

variable "flow_logs_retention_days" {
  description = "Number of days to retain VPC Flow Logs"
  type        = number
  default     = 30
}

# Access Control
variable "enforce_mfa" {
  description = "Enforce MFA for all IAM users"
  type        = bool
  default     = true
}

variable "password_policy" {
  description = "IAM password policy configuration"
  type = object({
    minimum_password_length        = number
    require_lowercase_characters   = bool
    require_numbers               = bool
    require_uppercase_characters  = bool
    require_symbols              = bool
    allow_users_to_change_password = bool
    max_password_age             = number
    password_reuse_prevention    = number
  })
  default = {
    minimum_password_length        = 14
    require_lowercase_characters   = true
    require_numbers               = true
    require_uppercase_characters  = true
    require_symbols              = true
    allow_users_to_change_password = true
    max_password_age             = 90
    password_reuse_prevention    = 24
  }
}

# Data Protection
variable "default_encryption" {
  description = "Enable default encryption for supported services"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain automated backups"
  type        = number
  default     = 35

  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 35
    error_message = "Backup retention must be between 7 and 35 days."
  }
}

# Monitoring and Alerting
variable "alert_endpoints" {
  description = "Configuration for alert endpoints"
  type = object({
    slack_webhook_url    = string
    teams_webhook_url    = string
    pagerduty_service_key = string
  })
  default = {
    slack_webhook_url    = ""
    teams_webhook_url    = ""
    pagerduty_service_key = ""
  }
  sensitive = true
}

variable "security_contacts" {
  description = "Security team contact information"
  type = object({
    primary_email     = string
    secondary_email   = string
    phone_number     = string
    escalation_email = string
  })
  default = {
    primary_email     = "security@company.com"
    secondary_email   = "security-backup@company.com"
    phone_number     = "+1-800-SECURITY"
    escalation_email = "security-escalation@company.com"
  }
}

# Cost Controls
variable "enable_cost_alerts" {
  description = "Enable cost-based alerts for security services"
  type        = bool
  default     = true
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit for security services (USD)"
  type        = number
  default     = 1000

  validation {
    condition     = var.monthly_budget_limit > 0
    error_message = "Monthly budget limit must be greater than 0."
  }
}

# Regional Configuration
variable "multi_region_trail" {
  description = "Enable multi-region CloudTrail"
  type        = bool
  default     = true
}

variable "additional_regions" {
  description = "Additional AWS regions to monitor"
  type        = list(string)
  default     = ["us-east-1", "us-west-2", "eu-west-1"]
}

# Data Residency and Sovereignty
variable "data_residency_region" {
  description = "Primary region for data residency compliance"
  type        = string
  default     = "us-east-1"
}

variable "cross_region_backup" {
  description = "Enable cross-region backup for critical security data"
  type        = bool
  default     = true
}

# Automation Settings
variable "auto_remediation" {
  description = "Enable automatic remediation for security findings"
  type        = bool
  default     = false
}

variable "remediation_lambda_timeout" {
  description = "Timeout for remediation Lambda functions (seconds)"
  type        = number
  default     = 300

  validation {
    condition     = var.remediation_lambda_timeout >= 60 && var.remediation_lambda_timeout <= 900
    error_message = "Lambda timeout must be between 60 and 900 seconds."
  }
}

# Testing and Validation
variable "enable_security_testing" {
  description = "Enable automated security testing"
  type        = bool
  default     = true
}

variable "penetration_testing_schedule" {
  description = "Cron expression for automated penetration testing"
  type        = string
  default     = "0 2 * * 0"  # Every Sunday at 2 AM
}

# Integration Settings
variable "siem_integration" {
  description = "SIEM integration configuration"
  type = object({
    enabled           = bool
    siem_type        = string  # splunk, elasticsearch, qradar, sentinel
    endpoint_url     = string
    api_key          = string
    index_prefix     = string
  })
  default = {
    enabled           = false
    siem_type        = "elasticsearch"
    endpoint_url     = ""
    api_key          = ""
    index_prefix     = "aws-security"
  }
  sensitive = true
}

variable "ticketing_system" {
  description = "Ticketing system integration for security incidents"
  type = object({
    enabled      = bool
    system_type  = string  # jira, servicenow, github
    api_url      = string
    api_token    = string
    project_key  = string
  })
  default = {
    enabled      = false
    system_type  = "jira"
    api_url      = ""
    api_token    = ""
    project_key  = "SEC"
  }
  sensitive = true
}

# Advanced Threat Protection
variable "threat_intelligence_feeds" {
  description = "External threat intelligence feed URLs"
  type        = list(string)
  default     = []
}

variable "custom_detection_rules" {
  description = "Custom security detection rules"
  type = list(object({
    name        = string
    description = string
    severity    = string
    rule_type   = string
    conditions  = map(string)
  }))
  default = []
}

# Performance and Scaling
variable "log_processing_parallelism" {
  description = "Number of parallel log processing workers"
  type        = number
  default     = 4

  validation {
    condition     = var.log_processing_parallelism >= 1 && var.log_processing_parallelism <= 10
    error_message = "Log processing parallelism must be between 1 and 10."
  }
}

variable "metric_buffer_size" {
  description = "Buffer size for security metrics (MB)"
  type        = number
  default     = 100

  validation {
    condition     = var.metric_buffer_size >= 10 && var.metric_buffer_size <= 1000
    error_message = "Metric buffer size must be between 10 and 1000 MB."
  }
}