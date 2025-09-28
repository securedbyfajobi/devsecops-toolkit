# Azure Security Baseline Terraform Module
# Implements comprehensive Azure security best practices and hardening
# Based on Azure Security Benchmark and Microsoft Cloud Security Framework

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_deleted_secrets_on_destroy = true
      recover_soft_deleted_secrets          = true
    }
    log_analytics_workspace {
      permanently_delete_on_destroy = true
    }
  }
}

locals {
  common_tags = merge(var.tags, {
    Module     = "azure-security-baseline"
    ManagedBy  = "terraform"
    CreatedBy  = "security-team"
    Purpose    = "security-hardening"
  })
}

# Resource Group
resource "azurerm_resource_group" "security" {
  name     = "${var.name_prefix}-security-rg"
  location = var.location

  tags = local.common_tags
}

# Log Analytics Workspace for centralized logging
resource "azurerm_log_analytics_workspace" "security" {
  name                = "${var.name_prefix}-security-law"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  sku                = var.log_analytics_sku
  retention_in_days   = var.log_retention_days

  tags = local.common_tags
}

# Key Vault for secrets management
resource "azurerm_key_vault" "security" {
  name                        = "${var.name_prefix}-security-kv"
  location                    = azurerm_resource_group.security.location
  resource_group_name         = azurerm_resource_group.security.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = var.key_vault_soft_delete_retention
  purge_protection_enabled    = true
  sku_name                   = "premium"

  enable_rbac_authorization = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.allowed_ip_ranges
  }

  tags = local.common_tags
}

# Storage Account for security logs
resource "azurerm_storage_account" "security_logs" {
  name                     = "${replace(var.name_prefix, "-", "")}securitylogs"
  resource_group_name      = azurerm_resource_group.security.name
  location                 = azurerm_resource_group.security.location
  account_tier             = "Standard"
  account_replication_type = var.storage_replication_type

  min_tls_version                = "TLS1_2"
  allow_nested_items_to_be_public = false
  enable_https_traffic_only       = true

  blob_properties {
    versioning_enabled  = true
    change_feed_enabled = true

    delete_retention_policy {
      days = var.blob_retention_days
    }

    container_delete_retention_policy {
      days = var.container_retention_days
    }
  }

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
  }

  tags = local.common_tags
}

# Storage Account Advanced Threat Protection
resource "azurerm_advanced_threat_protection" "storage_security" {
  target_resource_id = azurerm_storage_account.security_logs.id
  enabled            = true
}

# Security Center (Defender for Cloud)
resource "azurerm_security_center_subscription_pricing" "vm" {
  count = var.enable_defender_for_cloud ? 1 : 0

  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "sql" {
  count = var.enable_defender_for_cloud ? 1 : 0

  tier          = "Standard"
  resource_type = "SqlServers"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  count = var.enable_defender_for_cloud ? 1 : 0

  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "kubernetes" {
  count = var.enable_defender_for_cloud ? 1 : 0

  tier          = "Standard"
  resource_type = "KubernetesService"
}

resource "azurerm_security_center_subscription_pricing" "app_service" {
  count = var.enable_defender_for_cloud ? 1 : 0

  tier          = "Standard"
  resource_type = "AppServices"
}

# Security Center Auto Provisioning
resource "azurerm_security_center_auto_provisioning" "security" {
  auto_provision = "On"
}

# Security Center Workspace
resource "azurerm_security_center_workspace" "security" {
  scope        = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  workspace_id = azurerm_log_analytics_workspace.security.id
}

# Activity Log diagnostic settings
resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name               = "${var.name_prefix}-activity-log-diagnostics"
  target_resource_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"

  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id
  storage_account_id         = azurerm_storage_account.security_logs.id

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "ServiceHealth"
  }

  enabled_log {
    category = "Alert"
  }

  enabled_log {
    category = "Recommendation"
  }

  enabled_log {
    category = "Policy"
  }

  enabled_log {
    category = "Autoscale"
  }

  enabled_log {
    category = "ResourceHealth"
  }

  metric {
    category = "AllMetrics"
    enabled  = true

    retention_policy {
      enabled = true
      days    = var.metrics_retention_days
    }
  }
}

# Network Security Group with restrictive rules
resource "azurerm_network_security_group" "security" {
  name                = "${var.name_prefix}-security-nsg"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name

  # Deny all inbound traffic by default
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Allow HTTPS inbound
  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Allow SSH from specific IPs only
  dynamic "security_rule" {
    for_each = var.ssh_allowed_ips
    content {
      name                       = "AllowSSH-${security_rule.key}"
      priority                   = 1100 + security_rule.key
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "22"
      source_address_prefix      = security_rule.value
      destination_address_prefix = "*"
    }
  }

  tags = local.common_tags
}

# Network Watcher for network monitoring
resource "azurerm_network_watcher" "security" {
  count = var.enable_network_watcher ? 1 : 0

  name                = "${var.name_prefix}-network-watcher"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name

  tags = local.common_tags
}

# Azure Policy for compliance
resource "azurerm_policy_assignment" "security_baseline" {
  count = var.enable_azure_policy ? 1 : 0

  name                 = "${var.name_prefix}-security-baseline"
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/179d1daa-458f-4e47-8086-2a68d0d6c38f"  # Azure Security Benchmark
  description          = "Azure Security Benchmark compliance"
  display_name         = "Azure Security Baseline Policy"

  parameters = jsonencode({
    effect = {
      value = "AuditIfNotExists"
    }
  })

  identity {
    type = "SystemAssigned"
  }
}

# Role assignment for policy remediation
resource "azurerm_role_assignment" "policy_remediation" {
  count = var.enable_azure_policy ? 1 : 0

  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Contributor"
  principal_id         = azurerm_policy_assignment.security_baseline[0].identity[0].principal_id
}

# Azure Sentinel (if enabled)
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "security" {
  count                = var.enable_sentinel ? 1 : 0
  workspace_id         = azurerm_log_analytics_workspace.security.id
  customer_managed_key_enabled = false
}

# Sentinel data connectors
resource "azurerm_sentinel_data_connector_azure_active_directory" "security" {
  count                       = var.enable_sentinel ? 1 : 0
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id
}

resource "azurerm_sentinel_data_connector_azure_security_center" "security" {
  count                       = var.enable_sentinel ? 1 : 0
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id
}

resource "azurerm_sentinel_data_connector_office_365" "security" {
  count                       = var.enable_sentinel ? 1 : 0
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id

  exchange_enabled   = true
  sharepoint_enabled = true
  teams_enabled      = true
}

# Azure Monitor Action Group for alerts
resource "azurerm_monitor_action_group" "security" {
  name                = "${var.name_prefix}-security-alerts"
  resource_group_name = azurerm_resource_group.security.name
  short_name          = "secalerts"

  dynamic "email_receiver" {
    for_each = var.security_alert_emails
    content {
      name          = "email-${email_receiver.key}"
      email_address = email_receiver.value
    }
  }

  dynamic "sms_receiver" {
    for_each = var.security_alert_phone_numbers
    content {
      name         = "sms-${sms_receiver.key}"
      country_code = sms_receiver.value.country_code
      phone_number = sms_receiver.value.phone_number
    }
  }

  tags = local.common_tags
}

# Security alerts
resource "azurerm_monitor_metric_alert" "vm_cpu_high" {
  count = var.enable_security_alerts ? 1 : 0

  name                = "${var.name_prefix}-vm-cpu-high"
  resource_group_name = azurerm_resource_group.security.name
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]
  description         = "High CPU usage on virtual machines"
  severity            = 2

  criteria {
    metric_namespace = "Microsoft.Compute/virtualMachines"
    metric_name      = "Percentage CPU"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80

    dimension {
      name     = "VMName"
      operator = "Include"
      values   = ["*"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_activity_log_alert" "service_health" {
  count = var.enable_security_alerts ? 1 : 0

  name                = "${var.name_prefix}-service-health-alert"
  resource_group_name = azurerm_resource_group.security.name
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]
  description         = "Service health incidents"

  criteria {
    category = "ServiceHealth"
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }

  tags = local.common_tags
}

# Backup vault for critical resources
resource "azurerm_data_protection_backup_vault" "security" {
  count = var.enable_backup ? 1 : 0

  name                = "${var.name_prefix}-backup-vault"
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location
  datastore_type      = "VaultStore"
  redundancy          = var.backup_redundancy

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags
}

# Private DNS zone for Key Vault
resource "azurerm_private_dns_zone" "keyvault" {
  count = var.enable_private_endpoints ? 1 : 0

  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.security.name

  tags = local.common_tags
}

# Application Insights for security monitoring
resource "azurerm_application_insights" "security" {
  count = var.enable_application_insights ? 1 : 0

  name                = "${var.name_prefix}-security-insights"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  workspace_id        = azurerm_log_analytics_workspace.security.id
  application_type    = "web"

  tags = local.common_tags
}

# Automation Account for security automation
resource "azurerm_automation_account" "security" {
  count = var.enable_automation ? 1 : 0

  name                = "${var.name_prefix}-security-automation"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  sku_name           = "Basic"

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags
}

# Link Automation Account to Log Analytics
resource "azurerm_log_analytics_linked_service" "security" {
  count = var.enable_automation ? 1 : 0

  resource_group_name = azurerm_resource_group.security.name
  workspace_id        = azurerm_log_analytics_workspace.security.id
  read_access_id      = azurerm_automation_account.security[0].id
}

# Azure Firewall (if enabled)
resource "azurerm_public_ip" "firewall" {
  count = var.enable_azure_firewall ? 1 : 0

  name                = "${var.name_prefix}-firewall-pip"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  allocation_method   = "Static"
  sku                = "Standard"

  tags = local.common_tags
}

resource "azurerm_firewall" "security" {
  count = var.enable_azure_firewall ? 1 : 0

  name                = "${var.name_prefix}-firewall"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  sku_name           = "AZFW_VNet"
  sku_tier           = "Standard"

  ip_configuration {
    name                 = "configuration"
    subnet_id            = var.firewall_subnet_id
    public_ip_address_id = azurerm_public_ip.firewall[0].id
  }

  tags = local.common_tags
}

# Azure Firewall Policy
resource "azurerm_firewall_policy" "security" {
  count = var.enable_azure_firewall ? 1 : 0

  name                = "${var.name_prefix}-firewall-policy"
  resource_group_name = azurerm_resource_group.security.name
  location            = azurerm_resource_group.security.location

  threat_intelligence_mode = "Alert"

  threat_intelligence_allowlist {
    ip_addresses = var.firewall_threat_intel_allowlist_ips
    fqdns        = var.firewall_threat_intel_allowlist_fqdns
  }

  tags = local.common_tags
}

# Data sources
data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}