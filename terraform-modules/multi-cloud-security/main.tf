# Multi-Cloud Security Baseline Terraform Module
# Implements security controls across AWS, Azure, and GCP
# Provides unified security posture management and compliance

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

locals {
  common_tags = merge(var.tags, {
    Module      = "multi-cloud-security"
    ManagedBy   = "terraform"
    CreatedBy   = "security-team"
    Purpose     = "multi-cloud-security-hardening"
    CloudSetup  = "hybrid"
  })
}

# Random suffix for globally unique names
resource "random_id" "suffix" {
  byte_length = 4
}

# ==============================================================================
# AWS Security Configuration
# ==============================================================================

module "aws_security_baseline" {
  count = var.enable_aws ? 1 : 0

  source = "../aws-security-baseline"

  name_prefix                    = "${var.name_prefix}-aws"
  environment                   = var.environment
  tags                          = local.common_tags

  # Core security services
  enable_cloudtrail             = var.aws_config.enable_cloudtrail
  enable_config                 = var.aws_config.enable_config
  enable_guardduty              = var.aws_config.enable_guardduty
  enable_security_hub           = var.aws_config.enable_security_hub
  enable_sns_alerts             = var.aws_config.enable_sns_alerts
  enable_cloudwatch_alarms      = var.aws_config.enable_cloudwatch_alarms

  # Compliance frameworks
  compliance_frameworks         = var.compliance_frameworks

  # Alert configuration
  security_alert_emails         = var.security_contacts.email_addresses

  # Retention settings
  cloudtrail_log_retention_days = var.log_retention_days
  cloudwatch_log_retention_days = var.log_retention_days

  providers = {
    aws = aws
  }
}

# AWS Organizations SCPs for multi-account governance
resource "aws_organizations_policy" "security_guardrails" {
  count = var.enable_aws && var.aws_config.enable_organizations_scp ? 1 : 0

  name        = "${var.name_prefix}-security-guardrails"
  description = "Security guardrails for multi-cloud environment"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyDisableSecurityServices"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "guardduty:DeleteDetector",
          "securityhub:DisableSecurityHub"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = var.aws_config.organization_id
          }
        }
      },
      {
        Sid    = "EnforceEncryption"
        Effect = "Deny"
        Action = [
          "s3:PutObject",
          "rds:CreateDBInstance",
          "ec2:RunInstances"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "DenyPublicS3Buckets"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPublicAccessBlock"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-request-payer" = "BucketOwner"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# ==============================================================================
# Azure Security Configuration
# ==============================================================================

module "azure_security_baseline" {
  count = var.enable_azure ? 1 : 0

  source = "../azure-security-baseline"

  name_prefix = "${var.name_prefix}-azure-${random_id.suffix.hex}"
  location    = var.azure_config.location
  tags        = local.common_tags

  # Core security services
  enable_defender_for_cloud     = var.azure_config.enable_defender_for_cloud
  enable_sentinel               = var.azure_config.enable_sentinel
  enable_azure_policy           = var.azure_config.enable_azure_policy
  enable_network_watcher        = var.azure_config.enable_network_watcher
  enable_security_alerts        = var.azure_config.enable_security_alerts

  # Configuration
  log_retention_days            = var.log_retention_days
  security_alert_emails         = var.security_contacts.email_addresses
  allowed_ip_ranges             = var.azure_config.allowed_ip_ranges

  providers = {
    azurerm = azurerm
  }
}

# Azure Management Groups for governance
resource "azurerm_management_group" "security" {
  count = var.enable_azure && var.azure_config.enable_management_groups ? 1 : 0

  display_name = "${var.name_prefix}-security-mg"

  subscription_ids = var.azure_config.subscription_ids
}

# Azure Policy Set for multi-cloud compliance
resource "azurerm_policy_set_definition" "multi_cloud_security" {
  count = var.enable_azure ? 1 : 0

  name         = "${var.name_prefix}-multi-cloud-security"
  policy_type  = "Custom"
  display_name = "Multi-Cloud Security Policy Set"
  description  = "Comprehensive security policies for multi-cloud environment"

  parameters = jsonencode({
    allowedLocations = {
      type = "Array"
      metadata = {
        description = "The list of allowed locations for resources"
        displayName = "Allowed locations"
      }
      defaultValue = var.azure_config.allowed_locations
    }
  })

  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"  # Allowed locations
    parameter_values = jsonencode({
      listOfAllowedLocations = {
        value = "[parameters('allowedLocations')]"
      }
    })
  }

  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/a451c1ef-c6ca-483d-87ed-f49761e3ffb5"  # Require SSL for storage
  }

  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"  # Require encryption for VMs
  }
}

# ==============================================================================
# GCP Security Configuration
# ==============================================================================

# GCP Organization Policy Constraints
resource "google_organization_policy" "require_ssl" {
  count = var.enable_gcp ? 1 : 0

  org_id     = var.gcp_config.organization_id
  constraint = "compute.requireSslOnly"

  boolean_policy {
    enforced = true
  }
}

resource "google_organization_policy" "disable_serial_port" {
  count = var.enable_gcp ? 1 : 0

  org_id     = var.gcp_config.organization_id
  constraint = "compute.disableSerialPortAccess"

  boolean_policy {
    enforced = true
  }
}

resource "google_organization_policy" "require_shielded_vm" {
  count = var.enable_gcp ? 1 : 0

  org_id     = var.gcp_config.organization_id
  constraint = "compute.requireShieldedVm"

  boolean_policy {
    enforced = true
  }
}

resource "google_organization_policy" "restrict_public_ip" {
  count = var.enable_gcp ? 1 : 0

  org_id     = var.gcp_config.organization_id
  constraint = "compute.vmExternalIpAccess"

  list_policy {
    deny {
      all = true
    }
  }
}

# GCP Security Command Center
resource "google_security_center_notification_config" "security" {
  count = var.enable_gcp && var.gcp_config.enable_security_center ? 1 : 0

  config_id    = "${var.name_prefix}-security-notifications"
  organization = var.gcp_config.organization_id
  description  = "Multi-cloud security notifications"
  pubsub_topic = google_pubsub_topic.security_notifications[0].id

  streaming_config {
    filter = "state=\"ACTIVE\""
  }
}

resource "google_pubsub_topic" "security_notifications" {
  count = var.enable_gcp && var.gcp_config.enable_security_center ? 1 : 0

  name    = "${var.name_prefix}-security-notifications"
  project = var.gcp_config.project_id

  labels = {
    environment = var.environment
    purpose     = "security-notifications"
  }
}

# GCP Cloud Asset Inventory for security monitoring
resource "google_cloud_asset_organization_feed" "security" {
  count = var.enable_gcp ? 1 : 0

  billing_project  = var.gcp_config.project_id
  org_id          = var.gcp_config.organization_id
  feed_id         = "${var.name_prefix}-security-feed"
  content_type    = "RESOURCE"

  asset_types = [
    "compute.googleapis.com/Instance",
    "storage.googleapis.com/Bucket",
    "iam.googleapis.com/Role",
    "iam.googleapis.com/ServiceAccount"
  ]

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.security_notifications[0].id
    }
  }

  condition {
    expression = "!temporal_asset.deleted && temporal_asset.asset.asset_type:\"storage.googleapis.com/Bucket\""
    title      = "GCS Bucket Changes"
    description = "Monitor GCS bucket changes for security compliance"
  }
}

# ==============================================================================
# Cross-Cloud Security Monitoring
# ==============================================================================

# Cross-cloud security dashboard configuration
locals {
  cross_cloud_dashboard_config = {
    aws_enabled    = var.enable_aws
    azure_enabled  = var.enable_azure
    gcp_enabled    = var.enable_gcp

    aws_resources = var.enable_aws ? {
      cloudtrail_arn    = try(module.aws_security_baseline[0].cloudtrail_arn, null)
      security_hub_arn  = try(module.aws_security_baseline[0].security_hub_arn, null)
      sns_topic_arn     = try(module.aws_security_baseline[0].security_alerts_topic_arn, null)
    } : {}

    azure_resources = var.enable_azure ? {
      log_analytics_workspace_id = try(module.azure_security_baseline[0].log_analytics_workspace_id, null)
      resource_group_name        = try(module.azure_security_baseline[0].resource_group_name, null)
      action_group_id           = try(module.azure_security_baseline[0].action_group_id, null)
    } : {}

    gcp_resources = var.enable_gcp ? {
      security_topic = try(google_pubsub_topic.security_notifications[0].name, null)
      project_id     = var.gcp_config.project_id
      organization_id = var.gcp_config.organization_id
    } : {}
  }
}

# Unified security configuration file
resource "local_file" "security_dashboard_config" {
  content = jsonencode({
    version = "1.0"
    created = timestamp()

    multi_cloud_config = {
      name_prefix   = var.name_prefix
      environment   = var.environment
      clouds_enabled = {
        aws   = var.enable_aws
        azure = var.enable_azure
        gcp   = var.enable_gcp
      }

      compliance_frameworks = var.compliance_frameworks
      log_retention_days   = var.log_retention_days

      security_contacts = var.security_contacts

      cloud_resources = local.cross_cloud_dashboard_config

      unified_monitoring = {
        enabled = var.enable_unified_monitoring
        siem_integration = var.siem_integration

        alert_aggregation = {
          enabled = true
          threshold_critical = var.alert_thresholds.critical
          threshold_high    = var.alert_thresholds.high
          threshold_medium  = var.alert_thresholds.medium
        }

        compliance_reporting = {
          enabled = true
          frequency = var.compliance_reporting_frequency
          formats = ["json", "pdf", "csv"]
        }
      }

      cost_optimization = {
        enabled = var.enable_cost_optimization
        budget_alerts = {
          aws_monthly_limit   = var.cost_limits.aws_monthly
          azure_monthly_limit = var.cost_limits.azure_monthly
          gcp_monthly_limit   = var.cost_limits.gcp_monthly
        }
      }
    }
  })

  filename = "${path.module}/outputs/multi-cloud-security-config.json"
}

# Cross-cloud security metrics aggregation
resource "local_file" "security_metrics_config" {
  content = templatefile("${path.module}/templates/security-metrics.yml.tpl", {
    aws_enabled   = var.enable_aws
    azure_enabled = var.enable_azure
    gcp_enabled   = var.enable_gcp

    aws_cloudwatch_namespace    = "AWS/SecurityHub"
    azure_log_analytics_workspace = var.enable_azure ? module.azure_security_baseline[0].log_analytics_workspace_id : ""
    gcp_monitoring_project      = var.gcp_config.project_id

    alert_endpoints = var.alert_endpoints
    compliance_frameworks = var.compliance_frameworks
  })

  filename = "${path.module}/outputs/security-metrics-config.yml"
}

# ==============================================================================
# Data Sources
# ==============================================================================

data "aws_caller_identity" "current" {
  count = var.enable_aws ? 1 : 0
}

data "azurerm_client_config" "current" {
  count = var.enable_azure ? 1 : 0
}

data "google_client_config" "current" {
  count = var.enable_gcp ? 1 : 0
}