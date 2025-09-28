# Infrastructure Security Modules

This directory contains enterprise-grade Terraform modules for implementing comprehensive security across cloud infrastructure. These modules follow security best practices and compliance frameworks to ensure a robust security posture.

## 🏗️ Available Modules

### 1. AWS Security Baseline
**Directory**: `aws-security-baseline/`

Comprehensive AWS security implementation including:
- **CloudTrail**: API audit logging with encryption
- **AWS Config**: Compliance monitoring and rules
- **GuardDuty**: Threat detection and response
- **Security Hub**: Centralized security findings
- **KMS**: Encryption key management
- **SNS**: Security alerting and notifications
- **CloudWatch**: Security monitoring and alarms

**Key Features**:
- CIS AWS Foundations Benchmark compliance
- Multi-region security configuration
- Automated remediation capabilities
- Cost optimization controls
- SIEM integration ready

### 2. AWS Secure VPC
**Directory**: `aws-secure-vpc/`

Hardened VPC implementation with:
- **Network Segmentation**: Public/private subnet isolation
- **Security Groups**: Restrictive security rules
- **NACLs**: Network-level access controls
- **VPC Flow Logs**: Network traffic monitoring
- **NAT Gateways**: Secure outbound connectivity
- **Route Tables**: Controlled routing configuration

**Security Controls**:
- No auto-assignment of public IPs
- Restrictive network ACLs by default
- Encrypted flow logs
- Multi-AZ high availability

### 3. Azure Security Baseline
**Directory**: `azure-security-baseline/`

Comprehensive Azure security foundation:
- **Defender for Cloud**: Advanced threat protection
- **Azure Sentinel**: SIEM and SOAR capabilities
- **Key Vault**: Secrets management with RBAC
- **Log Analytics**: Centralized logging and monitoring
- **Azure Policy**: Governance and compliance
- **Network Security**: NSGs and Azure Firewall
- **Backup Vault**: Data protection and recovery

**Compliance Standards**:
- Azure Security Benchmark
- CIS Azure Foundations
- PCI DSS controls
- GDPR data protection

### 4. Multi-Cloud Security
**Directory**: `multi-cloud-security/`

Unified security across AWS, Azure, and GCP:
- **Cross-Cloud Governance**: Unified policy enforcement
- **Security Orchestration**: Centralized security management
- **Compliance Reporting**: Multi-cloud compliance dashboards
- **Incident Response**: Coordinated security operations
- **Cost Optimization**: Cross-cloud security cost management

**Advanced Features**:
- Cloud-agnostic security policies
- Unified monitoring and alerting
- Cross-cloud resource inventory
- Compliance framework mapping

## 🚀 Quick Start Guide

### 1. AWS Security Baseline Deployment

```hcl
module "aws_security_baseline" {
  source = "./terraform-modules/aws-security-baseline"

  name_prefix  = "company-security"
  environment  = "production"

  # Core security services
  enable_cloudtrail    = true
  enable_config        = true
  enable_guardduty     = true
  enable_security_hub  = true

  # Compliance frameworks
  compliance_frameworks = ["CIS", "AWS_FOUNDATIONAL", "PCI_DSS"]

  # Alert configuration
  security_alert_emails = [
    "security@company.com",
    "compliance@company.com"
  ]

  # Retention settings
  cloudtrail_log_retention_days = 2555  # 7 years
  cloudwatch_log_retention_days = 365   # 1 year

  tags = {
    Owner       = "security-team"
    Environment = "production"
    Project     = "security-baseline"
  }
}
```

### 2. Multi-Cloud Security Setup

```hcl
module "multi_cloud_security" {
  source = "./terraform-modules/multi-cloud-security"

  name_prefix = "company-multicloud"
  environment = "production"

  # Enable cloud providers
  enable_aws   = true
  enable_azure = true
  enable_gcp   = true

  # AWS configuration
  aws_config = {
    enable_cloudtrail    = true
    enable_guardduty     = true
    enable_security_hub  = true
    organization_id      = "o-1234567890"
  }

  # Azure configuration
  azure_config = {
    location                  = "East US"
    enable_defender_for_cloud = true
    enable_sentinel          = true
    subscription_ids         = ["sub-12345"]
  }

  # GCP configuration
  gcp_config = {
    project_id      = "company-security-123"
    organization_id = "123456789012"
    enable_security_center = true
  }

  # Unified configuration
  compliance_frameworks = ["CIS", "SOC2", "PCI_DSS"]
  log_retention_days   = 365

  security_contacts = {
    email_addresses = ["security@company.com"]
    phone_numbers   = ["+1-800-SECURITY"]
  }
}
```

### 3. Secure VPC Deployment

```hcl
module "secure_vpc" {
  source = "./terraform-modules/aws-secure-vpc"

  name_prefix  = "company-secure"
  environment  = "production"
  vpc_cidr     = "10.0.0.0/16"

  # Subnet configuration
  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs = ["10.0.10.0/24", "10.0.20.0/24"]

  # Security settings
  enable_nat_gateway = true
  enable_flow_logs   = true
  ssh_cidr_blocks    = ["203.0.113.0/24"]  # Admin subnet only

  tags = {
    Owner       = "infrastructure-team"
    Environment = "production"
    Security    = "high"
  }
}
```

## 🔧 Configuration Guide

### Environment-Specific Configurations

#### Development Environment
```hcl
# Development security baseline
module "dev_security" {
  source = "./terraform-modules/aws-security-baseline"

  name_prefix = "dev-security"
  environment = "development"

  # Relaxed settings for development
  enable_cloudtrail = true
  enable_config     = false  # Cost optimization
  enable_guardduty  = true

  cloudtrail_log_retention_days = 90   # Shorter retention
  security_alert_emails = ["dev-team@company.com"]

  # Cost controls
  monthly_budget_limit = 100
  enable_cost_alerts   = true
}
```

#### Production Environment
```hcl
# Production security baseline
module "prod_security" {
  source = "./terraform-modules/aws-security-baseline"

  name_prefix = "prod-security"
  environment = "production"

  # Full security suite
  enable_cloudtrail           = true
  enable_config              = true
  enable_guardduty           = true
  enable_security_hub        = true
  enable_macie               = true
  enable_inspector           = true

  # Enhanced settings
  auto_remediation           = true
  enable_cross_region_backup = true

  # Compliance requirements
  compliance_frameworks = [
    "CIS", "AWS_FOUNDATIONAL", "PCI_DSS", "SOC2", "HIPAA"
  ]

  # Extended retention
  cloudtrail_log_retention_days = 2555  # 7 years
  backup_retention_days        = 35     # Maximum

  security_alert_emails = [
    "security@company.com",
    "compliance@company.com",
    "ciso@company.com"
  ]
}
```

### Compliance Framework Mapping

#### CIS Controls Implementation
```hcl
variable "cis_controls" {
  description = "CIS Controls implementation mapping"
  type = map(object({
    control_id    = string
    description   = string
    aws_services  = list(string)
    azure_services = list(string)
    gcp_services  = list(string)
  }))

  default = {
    "CIS_1" = {
      control_id    = "CIS Control 1: Inventory and Control of Hardware Assets"
      description   = "Actively manage all hardware devices"
      aws_services  = ["config", "systems-manager"]
      azure_services = ["policy", "resource-graph"]
      gcp_services  = ["asset-inventory", "cloud-resource-manager"]
    }

    "CIS_3" = {
      control_id    = "CIS Control 3: Continuous Vulnerability Management"
      description   = "Continuously acquire, assess, and take action on new information"
      aws_services  = ["inspector", "guardduty", "security-hub"]
      azure_services = ["defender-for-cloud", "security-center"]
      gcp_services  = ["security-command-center", "container-analysis"]
    }

    "CIS_6" = {
      control_id    = "CIS Control 6: Maintenance, Monitoring and Analysis of Audit Logs"
      description   = "Collect, alert, review, and retain audit logs"
      aws_services  = ["cloudtrail", "cloudwatch"]
      azure_services = ["monitor", "log-analytics"]
      gcp_services  = ["cloud-logging", "cloud-monitoring"]
    }
  }
}
```

#### SOC 2 Type II Controls
```hcl
variable "soc2_controls" {
  description = "SOC 2 Type II controls implementation"
  type = map(object({
    trust_principle = string
    control_objective = string
    implementation = list(string)
  }))

  default = {
    "CC6.1" = {
      trust_principle = "Confidentiality"
      control_objective = "Logical and physical access controls"
      implementation = [
        "IAM policies and roles",
        "MFA enforcement",
        "Network segmentation",
        "Encryption at rest and in transit"
      ]
    }

    "CC7.1" = {
      trust_principle = "Confidentiality"
      control_objective = "System monitoring"
      implementation = [
        "CloudTrail logging",
        "Security monitoring",
        "Anomaly detection",
        "Incident response procedures"
      ]
    }
  }
}
```

## 📊 Security Monitoring Integration

### SIEM Integration Configuration
```hcl
# Splunk integration
module "security_baseline" {
  source = "./terraform-modules/aws-security-baseline"

  # ... other configuration ...

  siem_integration = {
    enabled      = true
    siem_type    = "splunk"
    endpoint_url = "https://splunk.company.com:8088"
    api_key      = var.splunk_hec_token
    index_prefix = "aws-security"
  }

  # Custom detection rules
  custom_detection_rules = [
    {
      name        = "Unusual Admin Activity"
      description = "Detect unusual administrative activities"
      severity    = "HIGH"
      rule_type   = "behavioral"
      conditions = {
        user_type = "admin"
        time_window = "after_hours"
        action_count = "> 10"
      }
    }
  ]
}
```

### Security Dashboard Integration
```hcl
# Grafana dashboard configuration
resource "local_file" "grafana_dashboard" {
  content = templatefile("${path.module}/templates/security-dashboard.json.tpl", {
    aws_cloudwatch_region = var.aws_region
    azure_workspace_id    = module.azure_security_baseline.log_analytics_workspace_id
    gcp_project_id       = var.gcp_project_id

    security_metrics = [
      "security_findings_critical",
      "security_findings_high",
      "compliance_score",
      "threat_detection_rate"
    ]
  })

  filename = "${path.module}/outputs/security-dashboard.json"
}
```

## 💰 Cost Optimization

### Cost Control Configuration
```hcl
module "cost_optimized_security" {
  source = "./terraform-modules/aws-security-baseline"

  # ... base configuration ...

  # Cost optimization settings
  enable_cost_optimization = true
  monthly_budget_limit     = 1000

  # Selective service enablement
  enable_macie     = false  # Expensive for large data volumes
  enable_inspector = true   # Cost-effective vulnerability scanning

  # Optimized retention
  cloudtrail_log_retention_days = 365   # Balance compliance and cost
  flow_logs_retention_days     = 30    # Short-term network analysis

  # Log processing optimization
  log_processing_parallelism = 2       # Reduce compute costs
  metric_buffer_size        = 50      # Optimize memory usage
}
```

### Multi-Cloud Cost Management
```hcl
module "multi_cloud_cost_control" {
  source = "./terraform-modules/multi-cloud-security"

  # ... other configuration ...

  cost_limits = {
    aws_monthly   = 500
    azure_monthly = 300
    gcp_monthly   = 200
  }

  enable_cost_optimization = true

  # Cloud-specific optimizations
  aws_config = {
    # ... other settings ...
    enable_macie = false      # High cost for data classification
    guardduty_finding_frequency = "ONE_HOUR"  # Reduce API calls
  }

  azure_config = {
    # ... other settings ...
    log_analytics_sku = "PerGB2018"  # Cost-effective pricing
    backup_redundancy = "LRS"        # Local redundancy for cost savings
  }
}
```

## 🚨 Incident Response Integration

### Automated Response Configuration
```hcl
module "security_with_automation" {
  source = "./terraform-modules/aws-security-baseline"

  # ... base configuration ...

  # Automated remediation
  auto_remediation = true
  remediation_lambda_timeout = 300

  # Custom remediation actions
  custom_remediation_rules = [
    {
      finding_type = "UnauthorizedAPICall"
      action      = "disable_user"
      approval_required = true
    },
    {
      finding_type = "CompromisedCredentials"
      action      = "rotate_credentials"
      approval_required = false
    }
  ]

  # Integration with ticketing system
  ticketing_system = {
    enabled      = true
    system_type  = "jira"
    api_url      = "https://company.atlassian.net"
    project_key  = "SEC"
  }
}
```

## 📋 Compliance Reporting

### Automated Compliance Reports
```hcl
# Compliance reporting configuration
resource "aws_lambda_function" "compliance_reporter" {
  filename         = "compliance-reporter.zip"
  function_name    = "${var.name_prefix}-compliance-reporter"
  role            = aws_iam_role.compliance_reporter.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 300

  environment {
    variables = {
      SECURITY_HUB_ARN = module.aws_security_baseline.security_hub_arn
      CONFIG_RULES     = jsonencode(module.aws_security_baseline.config_rules)
      COMPLIANCE_FRAMEWORKS = jsonencode(var.compliance_frameworks)
      REPORT_BUCKET    = aws_s3_bucket.compliance_reports.bucket
    }
  }
}

# Schedule compliance reports
resource "aws_cloudwatch_event_rule" "compliance_schedule" {
  name                = "${var.name_prefix}-compliance-schedule"
  description         = "Generate compliance reports"
  schedule_expression = "cron(0 8 * * 1)"  # Every Monday at 8 AM
}

resource "aws_cloudwatch_event_target" "compliance_lambda" {
  rule      = aws_cloudwatch_event_rule.compliance_schedule.name
  target_id = "ComplianceReporter"
  arn       = aws_lambda_function.compliance_reporter.arn
}
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Terraform State Management
```bash
# Initialize multi-cloud state management
terraform init -backend-config="bucket=company-terraform-state" \
               -backend-config="key=security/multi-cloud/terraform.tfstate" \
               -backend-config="region=us-east-1"

# Validate configuration across providers
terraform plan -var-file="environments/production.tfvars"

# Apply with confirmation
terraform apply -auto-approve=false
```

#### Provider Authentication
```bash
# AWS authentication
export AWS_PROFILE=security-admin
aws sts get-caller-identity

# Azure authentication
az login --service-principal -u $ARM_CLIENT_ID -p $ARM_CLIENT_SECRET --tenant $ARM_TENANT_ID
az account set --subscription $ARM_SUBSCRIPTION_ID

# GCP authentication
gcloud auth activate-service-account --key-file=service-account-key.json
gcloud config set project $GOOGLE_PROJECT
```

#### Resource Conflicts
```hcl
# Handle resource naming conflicts
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  unique_name = "${var.name_prefix}-${random_id.suffix.hex}"
}

# Use unique names for global resources
resource "aws_s3_bucket" "security_logs" {
  bucket = "${local.unique_name}-security-logs"
  # ... other configuration
}
```

## 📚 Additional Resources

### Security Best Practices Documentation
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)

### Compliance Frameworks
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO 27001:2013](https://www.iso.org/isoiec-27001-information-security.html)

### Security Tools Integration
- [Terraform Security Scanning](https://www.terraform.io/docs/cloud/sentinel/index.html)
- [tfsec Security Scanner](https://github.com/aquasecurity/tfsec)
- [Checkov Policy Scanner](https://github.com/bridgecrewio/checkov)

## 🤝 Contributing

To contribute to the infrastructure security modules:

1. **Fork** the repository
2. **Create** a feature branch for your security enhancement
3. **Test** thoroughly in a sandbox environment
4. **Document** security implications and compliance impact
5. **Submit** a pull request with security review checklist

### Security Review Checklist
- [ ] All secrets parameterized and not hardcoded
- [ ] Encryption enabled for data at rest and in transit
- [ ] Least privilege access principles applied
- [ ] Compliance framework requirements met
- [ ] Cost implications documented
- [ ] Security testing completed

---

## 🛡️ Security Excellence

These infrastructure security modules provide:

- **Defense in Depth**: Multiple layers of security controls
- **Zero Trust Architecture**: Never trust, always verify
- **Compliance Automation**: Automated compliance validation
- **Cost Optimization**: Security without breaking the budget
- **Multi-Cloud Support**: Consistent security across providers

**Remember**: Infrastructure security is the foundation of a robust security posture! 🏗️🔒