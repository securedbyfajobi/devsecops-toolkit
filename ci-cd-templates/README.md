# DevSecOps CI/CD Security Templates

This directory contains enterprise-grade security pipeline templates for major CI/CD platforms. These templates implement comprehensive security scanning, compliance validation, and automated security gates to ensure secure software delivery.

## 🚀 Available Templates

### GitHub Actions
- **File**: `github-security-workflow.yml`
- **Features**: CodeQL, Semgrep, Trivy, Snyk, secret detection, IaC security
- **Placement**: `.github/workflows/security.yml`

### GitLab CI/CD
- **File**: `.gitlab-ci-security.yml`
- **Features**: Built-in security scanners, Trivy, Checkov, enhanced security gates
- **Placement**: `.gitlab-ci.yml` or include in existing pipeline

### Azure DevOps
- **File**: `azure-devops-security-pipeline.yml`
- **Features**: Multi-language SAST, container scanning, compliance reporting
- **Placement**: `azure-pipelines.yml`

### Jenkins
- **File**: `Jenkinsfile-security`
- **Features**: Parallel scanning, comprehensive reporting, flexible security gates
- **Placement**: `Jenkinsfile` or separate security pipeline

### CircleCI
- **File**: `circleci-security-config.yml`
- **Features**: Orb-based scanning, workspace persistence, scheduled scans
- **Placement**: `.circleci/config.yml`

## 🔧 Configuration Files

### Security Hub Configuration
- **File**: `security-hub-config.yaml`
- **Purpose**: Configure AWS Security Hub analyzer settings, thresholds, and integrations

## 🛡️ Security Scanning Features

### Secret Detection
- **Tools**: GitLeaks, TruffleHog, detect-secrets
- **Coverage**: Git history, environment files, configuration files
- **Action**: Fail pipeline on secret detection

### Static Application Security Testing (SAST)
- **Tools**: CodeQL, Semgrep, Bandit, ESLint Security, Gosec
- **Languages**: Python, JavaScript/TypeScript, Go, Java, C#
- **Frameworks**: Custom rules for popular frameworks

### Dependency Vulnerability Scanning
- **Tools**: Snyk, Safety, npm audit, OWASP Dependency Check, Nancy
- **Coverage**: Direct and transitive dependencies
- **Formats**: requirements.txt, package.json, go.mod, pom.xml

### Container Security Scanning
- **Tools**: Trivy, Grype, Anchore
- **Coverage**: OS packages, application dependencies, misconfigurations
- **Standards**: CIS Docker Benchmark compliance

### Infrastructure as Code (IaC) Security
- **Tools**: Checkov, TFSec, kube-score, Terrascan
- **Coverage**: Terraform, CloudFormation, Kubernetes, Docker
- **Frameworks**: AWS, Azure, GCP security best practices

## 📊 Security Gates & Thresholds

### Default Thresholds
```yaml
Security Levels:
  Critical: 0 (block deployment)
  High: 5 (warning threshold)
  Medium: 20 (informational)
```

### Customizable Gates
- **Environment-based**: Different thresholds for dev/staging/prod
- **Repository-based**: Custom rules per project
- **Time-based**: Emergency deployment bypasses

## 🚀 Quick Start

### 1. Choose Your Platform
Select the appropriate template for your CI/CD platform:

```bash
# GitHub Actions
cp github-security-workflow.yml .github/workflows/security.yml

# GitLab CI/CD
cp .gitlab-ci-security.yml .gitlab-ci.yml

# Azure DevOps
cp azure-devops-security-pipeline.yml azure-pipelines.yml

# Jenkins
cp Jenkinsfile-security Jenkinsfile

# CircleCI
cp circleci-security-config.yml .circleci/config.yml
```

### 2. Configure Security Tools
Set up required environment variables and secrets:

```bash
# Required secrets (example for GitHub Actions)
SNYK_TOKEN=your_snyk_token
SEMGREP_APP_TOKEN=your_semgrep_token
DOCKER_REGISTRY_TOKEN=your_registry_token
```

### 3. Customize Thresholds
Edit security thresholds in your chosen template:

```yaml
variables:
  MAX_CRITICAL_VULNS: 0
  MAX_HIGH_VULNS: 5
  MAX_MEDIUM_VULNS: 20
```

### 4. Configure Notifications
Set up security team notifications:

```yaml
notifications:
  email: security-team@company.com
  slack_webhook: https://hooks.slack.com/...
  teams_webhook: https://company.webhook.office.com/...
```

## 🔧 Advanced Configuration

### Custom Security Rules
Create custom security rules for your organization:

```yaml
custom_rules:
  - name: "Company API Key Detection"
    pattern: "company-api-[a-zA-Z0-9]{32}"
    severity: "CRITICAL"

  - name: "Internal Service URLs"
    pattern: "https://internal\\.company\\.com"
    severity: "HIGH"
```

### Integration with Security Tools
Configure integration with enterprise security platforms:

```yaml
integrations:
  sonarqube:
    url: https://sonar.company.com
    token: ${SONAR_TOKEN}

  jira:
    url: https://company.atlassian.net
    project: SEC
    token: ${JIRA_TOKEN}

  defectdojo:
    url: https://defectdojo.company.com
    api_key: ${DEFECTDOJO_API_KEY}
```

### Policy as Code
Implement security policies as code:

```yaml
policies:
  dockerfile:
    - no_root_user: true
    - scan_base_images: true
    - require_health_check: true

  kubernetes:
    - no_privileged_containers: true
    - require_security_context: true
    - enforce_network_policies: true
```

## 📈 Monitoring & Reporting

### Security Metrics Dashboard
Track security metrics across your organization:

- **Vulnerability Trends**: Track vulnerability discovery and remediation
- **Security Gate Pass Rate**: Monitor deployment blocking frequency
- **MTTR (Mean Time to Remediation)**: Measure security issue resolution
- **Compliance Scores**: Track adherence to security standards

### Automated Reporting
Generate automated security reports:

```json
{
  "security_summary": {
    "timestamp": "2024-01-15T10:30:00Z",
    "repository": "company/app",
    "commit": "abc123",
    "scans_completed": {
      "sast": true,
      "dependency_scan": true,
      "container_scan": true,
      "secret_detection": true,
      "iac_security": true
    },
    "vulnerabilities": {
      "critical": 0,
      "high": 2,
      "medium": 8,
      "low": 15
    },
    "security_gate": "PASSED",
    "compliance_frameworks": [
      "OWASP Top 10",
      "NIST CSF",
      "CIS Controls"
    ]
  }
}
```

## 🎯 Compliance Frameworks

### Supported Standards
- **OWASP Top 10**: Web application security risks
- **NIST Cybersecurity Framework**: Comprehensive security controls
- **CIS Controls**: Critical security controls
- **ISO 27001**: Information security management
- **SANS Top 25**: Most dangerous software errors
- **PCI DSS**: Payment card industry security

### Compliance Mapping
Each security scan maps to specific compliance requirements:

```yaml
compliance_mapping:
  owasp_top_10:
    A01_broken_access_control: [sast, iac_security]
    A02_cryptographic_failures: [sast, secret_detection]
    A03_injection: [sast, dependency_scan]
    A06_vulnerable_components: [dependency_scan, container_scan]

  nist_csf:
    identify: [dependency_scan, iac_security]
    protect: [sast, secret_detection]
    detect: [container_scan, secret_detection]
    respond: [security_gate, notifications]
    recover: [automated_remediation]
```

## 🔄 CI/CD Integration Best Practices

### 1. Early and Often
- Run security scans on every commit
- Fail fast on critical vulnerabilities
- Provide quick feedback to developers

### 2. Shift Left Security
- IDE security plugins
- Pre-commit hooks
- Developer security training

### 3. Progressive Security
- Lightweight scans on feature branches
- Comprehensive scans on main branch
- Deep scans for releases

### 4. Automated Remediation
- Auto-update dependencies
- Auto-fix security configurations
- Generate security patches

## 🚨 Incident Response

### Security Pipeline Failures
When security gates fail:

1. **Immediate Actions**
   - Block deployment to production
   - Notify security team
   - Create security incident ticket

2. **Investigation**
   - Review security scan reports
   - Assess vulnerability impact
   - Determine remediation priority

3. **Remediation**
   - Fix critical vulnerabilities
   - Update dependencies
   - Apply security patches

4. **Verification**
   - Re-run security scans
   - Validate fixes
   - Update security documentation

### Emergency Procedures
For critical production issues:

```yaml
emergency_deployment:
  security_gate_bypass: true
  approvers: [security_lead, cto]
  notification: all_hands
  post_deployment_scan: required
```

## 📚 Training & Documentation

### Developer Security Training
- **Secure Coding**: OWASP guidelines, language-specific best practices
- **Tool Usage**: How to interpret and fix security scan results
- **Compliance**: Understanding regulatory requirements

### Security Champions Program
- **Embed Security**: Security champions in each development team
- **Knowledge Sharing**: Regular security workshops and brown bags
- **Continuous Learning**: Security certification and conference attendance

## 🔧 Troubleshooting

### Common Issues

#### False Positives
```yaml
# Configure suppressions
suppressions:
  semgrep:
    rules:
      - id: "rule-id"
        reason: "False positive - reviewed by security team"

  trivy:
    cves:
      - "CVE-2021-12345"  # Not applicable to our use case
```

#### Performance Optimization
```yaml
# Optimize scan performance
performance:
  parallel_jobs: 4
  cache_enabled: true
  incremental_scans: true
  scan_timeout: "30m"
```

#### Tool Configuration
```yaml
# Tool-specific configurations
tools:
  trivy:
    timeout: "10m"
    skip_db_update: false
    severity: "HIGH,CRITICAL"

  semgrep:
    config: "auto"
    timeout: "5m"
    max_target_bytes: "1GB"
```

## 🤝 Contributing

To contribute improvements to these security templates:

1. **Fork** the repository
2. **Create** a feature branch
3. **Test** security templates thoroughly
4. **Document** changes and new features
5. **Submit** a pull request

### Testing Templates
```bash
# Test GitHub Actions locally
act -j security-scan

# Test GitLab CI locally
gitlab-runner exec docker security_scan

# Validate Jenkins pipeline
jenkins-cli validate-jenkinsfile < Jenkinsfile-security
```

## 📞 Support

For questions, issues, or security concerns:

- **Security Team**: security@company.com
- **DevOps Team**: devops@company.com
- **Documentation**: https://docs.company.com/security
- **Training**: https://learning.company.com/security

---

## 🏆 Security Excellence

These templates represent security best practices and help achieve:

- **Zero Trust Security**: Never trust, always verify
- **Defense in Depth**: Multiple layers of security controls
- **Continuous Monitoring**: Real-time security visibility
- **Rapid Response**: Fast detection and remediation
- **Compliance Assurance**: Meet regulatory requirements

**Remember**: Security is everyone's responsibility! 🛡️