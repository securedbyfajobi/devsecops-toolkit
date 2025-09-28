# Container Security Scanner

Enterprise-grade container security scanning solution for DevSecOps pipelines.

## 🛡️ Overview

The Container Security Scanner provides comprehensive security analysis for container images, combining multiple vulnerability scanners with security best practice checks, secrets detection, and compliance validation.

## ✨ Features

- **Multi-Scanner Integration**: Trivy, Grype, Snyk, Clair, and more
- **Vulnerability Detection**: CVE scanning with CVSS scoring
- **Security Best Practices**: Dockerfile and container configuration analysis
- **Secrets Detection**: Identifies hardcoded credentials and API keys
- **Compliance Checking**: CIS Docker Benchmark, NIST 800-190, PCI DSS
- **Multi-Format Reports**: JSON, HTML, SARIF, CSV outputs
- **Cloud Integration**: AWS Security Hub, SIEM systems, notifications
- **CI/CD Ready**: Pipeline integration with configurable exit codes
- **Registry Support**: Docker Hub, ECR, GCR, ACR, Harbor

## 🚀 Quick Start

### Installation

1. **Clone and Setup**:
   ```bash
   cd devsecops-toolkit/container-security
   python setup.py
   ```

2. **Install External Scanners** (recommended):
   ```bash
   # Install Trivy
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

   # Install Grype
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
   ```

### Basic Usage

```bash
# Scan a container image
python container-scanner.py nginx:latest

# Generate HTML report
python container-scanner.py --output html --output-file report.html ubuntu:22.04

# SARIF output for security tools
python container-scanner.py --output sarif --output-file results.sarif myapp:v1.0
```

## 📊 Sample Output

```
🛡️ Container Security Scanner
🔍 Scanning: nginx:1.20-alpine
==================================================

📊 Running Trivy scan...
   ✅ Trivy found 15 vulnerabilities

🔒 Running security checks...
   ✅ Completed 8 security checks

📈 Scan Summary:
   Risk Score: 35.5/100
   Vulnerabilities: 15
   - Critical: 1
   - High: 3
   - Medium: 7
   - Low: 4
   Security Checks: 2 failed

🟡 MEDIUM RISK - Plan remediation
```

## 🔧 Configuration

Edit `config/container-security.yml` to customize scanner behavior:

```yaml
# Enable/disable scanners
scanners:
  trivy:
    enabled: true
    db_update: true
  grype:
    enabled: true
  snyk:
    enabled: false
    token: "${SNYK_TOKEN}"

# Security check configuration
security_checks:
  dockerfile_best_practices: true
  secrets_detection: true
  compliance_policies: true

# Severity thresholds
severity:
  threshold: "MEDIUM"
  fail_on_critical: true
  fail_on_high: true
```

## 🔍 Vulnerability Scanning

The scanner integrates multiple vulnerability databases:

- **Trivy**: Comprehensive CVE database with OS and language packages
- **Grype**: Anchore's vulnerability database
- **Snyk**: Commercial vulnerability intelligence
- **Clair**: CoreOS static analysis

## 🔒 Security Checks

### Dockerfile Best Practices
- Non-root user execution
- Health check configuration
- Minimal base images
- No exposed dangerous ports
- Proper labeling

### Secrets Detection
- API keys and tokens
- Private keys and certificates
- Database credentials
- Cloud provider keys

### Compliance Validation
- CIS Docker Benchmark
- NIST 800-190 Container Security Guide
- PCI DSS requirements
- SOX compliance checks

## 📄 Report Formats

### JSON Report
```json
{
  "scan_metadata": {
    "image": "nginx:latest",
    "scan_time": "2023-12-01T14:30:22Z",
    "risk_score": 35.5
  },
  "vulnerabilities": [...],
  "security_checks": [...],
  "summary": {
    "total_vulnerabilities": 15,
    "critical_vulnerabilities": 1,
    "failed_checks": 2
  }
}
```

### HTML Report
Interactive web report with:
- Executive summary dashboard
- Vulnerability details table
- Security check results
- Risk assessment charts
- Remediation guidance

### SARIF Report
Static Analysis Results Interchange Format for integration with:
- GitHub Security tab
- Azure DevOps
- GitLab Security Dashboard
- IDE security extensions

## ☁️ Cloud Integration

### AWS Security Hub
Export findings to AWS Security Hub:

```yaml
integrations:
  aws_security_hub:
    enabled: true
    region: "us-east-1"
    batch_size: 100
```

### SIEM Integration
Forward results to SIEM systems:

```yaml
integrations:
  elasticsearch:
    enabled: true
    endpoint: "https://elasticsearch.company.com:9200"
    index_prefix: "container-security"
```

## 🔄 CI/CD Integration

### GitHub Actions
```yaml
- name: Container Security Scan
  run: |
    python container-scanner.py \
      --output sarif \
      --output-file security-results.sarif \
      ${{ env.IMAGE_NAME }}:${{ env.IMAGE_TAG }}

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: security-results.sarif
```

### GitLab CI
```yaml
container_security:
  script:
    - python container-scanner.py --output json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

### Jenkins Pipeline
```groovy
stage('Container Security Scan') {
    steps {
        script {
            sh '''
                python container-scanner.py \
                  --output html \
                  --output-file security-report.html \
                  ${IMAGE_NAME}:${BUILD_NUMBER}
            '''
        }
    }
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'security-report.html',
                reportName: 'Container Security Report'
            ])
        }
    }
}
```

## 🎯 Risk Scoring

The scanner uses a weighted risk scoring algorithm:

- **Critical vulnerabilities**: 10 points each
- **High vulnerabilities**: 7 points each
- **Medium vulnerabilities**: 4 points each
- **Low vulnerabilities**: 1 point each
- **Critical security failures**: 15 points each
- **High security failures**: 10 points each

Risk levels:
- **0-20**: Low Risk ✅
- **21-40**: Medium Risk 🟡
- **41-70**: High Risk ⚠️
- **71-100**: Critical Risk 🚨

## 🔧 Command Line Options

```bash
python container-scanner.py [OPTIONS] IMAGE

Options:
  --config PATH              Configuration file path
  --output FORMAT            Output format (json|html|sarif|csv)
  --output-file PATH         Output file path
  --export-security-hub      Export to AWS Security Hub
  --severity-threshold LEVEL Minimum severity to report
  --fail-on-critical         Exit with code 1 on critical findings
  --quiet                    Suppress output except errors
  --help                     Show help message
```

## 🧪 Testing

Run the test suite:

```bash
# Basic validation tests
python basic_test.py

# Comprehensive test suite (requires pytest)
python test_container_scanner.py

# Simple functionality test
python simple_test.py
```

## 📚 Examples

### Scan Alpine Linux
```bash
python container-scanner.py alpine:latest
```

### Scan with Custom Configuration
```bash
python container-scanner.py --config /path/to/config.yml nginx:1.20
```

### Generate Executive Report
```bash
python container-scanner.py \
  --output html \
  --output-file executive-report.html \
  mycompany/webapp:v2.1.0
```

### CI/CD with Exit Codes
```bash
# Fail build on critical or high vulnerabilities
python container-scanner.py \
  --fail-on-critical \
  --output sarif \
  production-app:latest || exit 1
```

## 🔐 Security Considerations

- **Credentials**: Store sensitive configuration in environment variables
- **Network**: Scanner may need internet access for vulnerability database updates
- **Privileges**: Docker daemon access required for image inspection
- **Caching**: Vulnerability databases cached locally for performance

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and test: `python basic_test.py`
4. Commit changes: `git commit -am 'Add feature'`
5. Push to branch: `git push origin feature-name`
6. Submit pull request

## 📄 License

This project is part of the DevSecOps Toolkit and follows the same licensing terms.

## 🔗 Related Tools

- [AWS Security Hub Analyzer](../aws-security/)
- [Kubernetes Security Hardening](../kubernetes-security/)
- [CI/CD Security Templates](../ci-cd-templates/)
- [Security Monitoring Dashboard](../security-dashboard/)

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review configuration examples
3. Run diagnostic tests: `python basic_test.py`
4. Open an issue with scan logs and configuration