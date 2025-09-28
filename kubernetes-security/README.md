# Kubernetes Security Hardening

This directory contains comprehensive Kubernetes security configurations implementing defense-in-depth strategies, zero-trust networking, and enterprise-grade security monitoring.

## 🛡️ Security Components

### 1. Pod Security Standards (PSS)
**File**: `pod-security-standards.yaml`

Modern replacement for Pod Security Policies with enhanced security controls:

- **Privileged**: System components requiring elevated access
- **Baseline**: Default security for most workloads
- **Restricted**: Highest security for sensitive workloads
- **PCI DSS**: Compliance-focused configurations for payment processing
- **Development/Production**: Environment-specific security policies

**Key Features**:
- Pod Security Standards v1.28 compliance
- Custom security contexts and constraints
- AppArmor and Seccomp profiles
- Comprehensive capability restrictions

### 2. Network Security Policies
**File**: `network-security-policies.yaml`

Zero-trust network segmentation implementing micro-segmentation:

- **Default Deny-All**: Baseline security for all namespaces
- **Application Tier Policies**: Frontend, backend, database segregation
- **PCI DSS Compliance**: Strict network isolation for payment processing
- **Cross-Cluster Communication**: Multi-cluster security policies
- **Emergency Break-Glass**: Controlled emergency access procedures

**Architecture**:
```
Internet → Ingress → Frontend → Backend → Database
    ↓         ↓         ↓         ↓         ↓
   FW    LoadBalancer  Web     API     Data
         Security      Tier    Tier    Tier
```

### 3. Security Monitoring & Observability
**File**: `security-monitoring.yaml`

Comprehensive runtime security monitoring and threat detection:

- **Falco Runtime Security**: Real-time threat detection
- **Security Event Export**: SIEM integration via Fluentd
- **Prometheus Alerting**: Security-focused alerts and metrics
- **Incident Response**: Automated webhook notifications
- **Compliance Monitoring**: Continuous compliance validation

**Monitoring Coverage**:
- Container runtime anomalies
- Kubernetes API audit events
- Network policy violations
- Privilege escalation attempts
- Cryptocurrency mining detection
- Sensitive file access monitoring

### 4. RBAC Security Configuration
**File**: `rbac-security.yaml`

Role-based access control following principle of least privilege:

**Roles Included**:
- **Developer**: Read-only development access
- **Senior Developer**: Deployment access in dev environments
- **DevOps Engineer**: Cross-namespace operational access
- **Security Engineer**: Security policy management
- **SRE**: Production monitoring and troubleshooting
- **Auditor**: Compliance and audit access
- **Emergency Access**: Break-glass administrative access

**Service Accounts**:
- CI/CD Pipeline automation
- Monitoring and observability
- Backup operations
- Security monitoring

### 5. Legacy Pod Security Policy
**File**: `pod-security-policy.yaml`

Legacy PSP configuration for clusters not yet migrated to Pod Security Standards:

- Restrictive security policy
- RBAC integration
- Capability restrictions
- Volume and host access controls

## 🚀 Quick Start Guide

### 1. Deploy Pod Security Standards
```bash
# Create security namespaces and apply PSS
kubectl apply -f pod-security-standards.yaml

# Verify namespace security levels
kubectl get namespaces -o custom-columns=NAME:.metadata.name,ENFORCE:.metadata.labels."pod-security\.kubernetes\.io/enforce"
```

### 2. Implement Network Policies
```bash
# Apply network segmentation
kubectl apply -f network-security-policies.yaml

# Verify network policies
kubectl get networkpolicies --all-namespaces
```

### 3. Deploy Security Monitoring
```bash
# Create security monitoring namespace
kubectl create namespace security-system

# Deploy Falco and monitoring stack
kubectl apply -f security-monitoring.yaml

# Check security monitoring status
kubectl get pods -n security-system
```

### 4. Configure RBAC
```bash
# Apply RBAC configurations
kubectl apply -f rbac-security.yaml

# Verify role bindings
kubectl get clusterrolebindings -l rbac.kubernetes.io/team
```

## 🔧 Configuration Guide

### Environment-Specific Settings

#### Development Environment
- **Security Level**: Baseline Pod Security Standard
- **Network Policies**: Permissive within namespace
- **Monitoring**: Learning mode enabled
- **RBAC**: Extended developer permissions

#### Production Environment
- **Security Level**: Restricted Pod Security Standard
- **Network Policies**: Strict micro-segmentation
- **Monitoring**: Enhanced alerting and response
- **RBAC**: Minimal required permissions

#### PCI DSS Environment
- **Security Level**: Restricted with encryption requirements
- **Network Policies**: Isolated network segments
- **Monitoring**: Comprehensive audit logging
- **RBAC**: Segregation of duties enforced

### Security Policy Customization

#### Pod Security Standards
```yaml
# Custom namespace with specific security requirements
apiVersion: v1
kind: Namespace
metadata:
  name: custom-workload
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
    custom.company.com/data-classification: "confidential"
  annotations:
    pod-security.kubernetes.io/enforce-version: "v1.28"
    security.kubernetes.io/custom-policy: "financial-services"
```

#### Network Policy Templates
```yaml
# Template for application-specific network policies
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-specific-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: your-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: allowed-source
    ports:
    - protocol: TCP
      port: 8080
```

### Security Monitoring Configuration

#### Custom Falco Rules
```yaml
# Add to falco_rules.local.yaml ConfigMap
- rule: Custom Application Monitoring
  desc: Monitor specific application behaviors
  condition: >
    spawned_process and
    container.image.repository contains "your-app" and
    proc.name in (suspicious_processes)
  output: >
    Suspicious process in application container
    (container=%container.name process=%proc.name)
  priority: WARNING
  tags: [application, custom]
```

#### Security Alerts
```yaml
# Custom Prometheus alerting rules
- alert: CustomSecurityViolation
  expr: increase(falco_events_total{rule="Custom Application Monitoring"}[5m]) > 0
  for: 1m
  labels:
    severity: warning
    team: application-security
  annotations:
    summary: "Custom security policy violation"
    description: "Application security policy violated {{ $value }} times"
```

## 📊 Security Metrics & KPIs

### Key Security Indicators
- **Security Policy Violations**: Network and pod policy violations
- **Runtime Anomalies**: Suspicious container activities
- **RBAC Effectiveness**: Failed authorization attempts
- **Compliance Score**: Adherence to security standards
- **Mean Time to Detection (MTTD)**: Security incident detection speed
- **Mean Time to Response (MTTR)**: Incident response effectiveness

### Security Dashboard Queries
```promql
# Security policy violations
sum(rate(falco_events_total{priority=~"HIGH|CRITICAL"}[5m])) by (rule)

# Network policy denials
sum(rate(cilium_policy_verdict_total{verdict="DENIED"}[5m])) by (namespace)

# Failed API authentication
sum(rate(apiserver_audit_total{verb="create",objectRef_subresource="token",responseStatus_code!~"2.."}[5m]))

# Pod security policy violations
sum(rate(kube_pod_security_policy_violations_total[5m])) by (namespace, policy)
```

## 🔒 Compliance & Auditing

### Supported Compliance Frameworks
- **CIS Kubernetes Benchmark v1.8.0**
- **NIST Cybersecurity Framework**
- **NSA/CISA Kubernetes Hardening Guide**
- **PCI DSS Requirements**
- **SOC 2 Type II Controls**
- **ISO 27001 Information Security**

### Audit Reporting
```bash
# Generate compliance report
kubectl get events --field-selector type=Warning \
  --output json | jq '.items[] | select(.reason | test("Security|Policy|RBAC"))'

# Export security configurations for audit
kubectl get networkpolicies,podsecuritypolicies,roles,clusterroles \
  --all-namespaces -o yaml > security-audit-$(date +%Y%m%d).yaml
```

### Security Scan Integration
```bash
# Run kube-bench security benchmark
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Run kube-hunter security assessment
kubectl create job kube-hunter --image=aquasec/kube-hunter:latest

# Run falco security runtime scan
kubectl logs -n security-system daemonset/falco | grep -i "critical\|high"
```

## 🚨 Incident Response

### Security Incident Workflow
1. **Detection**: Falco alerts trigger incident response
2. **Triage**: Security team evaluates threat severity
3. **Containment**: Network policies isolate affected resources
4. **Investigation**: Audit logs and metrics analysis
5. **Remediation**: Apply security patches and policy updates
6. **Recovery**: Restore normal operations with enhanced monitoring

### Emergency Procedures
```bash
# Emergency network isolation
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-isolation
  namespace: affected-namespace
spec:
  podSelector:
    matchLabels:
      security.kubernetes.io/isolated: "true"
  policyTypes:
  - Ingress
  - Egress
EOF

# Emergency pod termination
kubectl delete pods -n affected-namespace -l security.kubernetes.io/compromised=true

# Enable emergency RBAC access (requires approval)
kubectl patch clusterrolebinding emergency-access-disabled \
  -p '{"metadata":{"labels":{"rbac.kubernetes.io/enabled":"true"}}}'
```

## 🔧 Troubleshooting

### Common Security Issues

#### Pod Security Policy Violations
```bash
# Check PSP violations
kubectl get events --field-selector reason=FailedCreate | grep -i security

# Validate pod security context
kubectl describe pod failing-pod | grep -A 10 "Security Context"
```

#### Network Policy Issues
```bash
# Test network connectivity
kubectl run test-pod --image=busybox --rm -it -- wget -O- http://target-service:8080

# Check network policy logs (with Cilium)
kubectl logs -n kube-system -l k8s-app=cilium | grep -i "policy\|denied"
```

#### RBAC Permission Issues
```bash
# Check user permissions
kubectl auth can-i create pods --as=user:john.doe

# Audit RBAC violations
kubectl get events --field-selector reason=Forbidden | grep -i rbac
```

### Performance Optimization
```bash
# Optimize Falco performance
kubectl patch daemonset falco -n security-system -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "falco",
          "resources": {
            "limits": {"cpu": "200m", "memory": "512Mi"},
            "requests": {"cpu": "100m", "memory": "256Mi"}
          }
        }]
      }
    }
  }
}'

# Scale security monitoring
kubectl scale deployment security-event-exporter -n security-system --replicas=3
```

## 📚 Additional Resources

### Security Best Practices
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA Kubernetes Hardening Guide](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)
- [OWASP Kubernetes Security](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)

### Security Tools Integration
- [Falco Runtime Security](https://falco.org/docs/)
- [Trivy Container Scanning](https://aquasecurity.github.io/trivy/)
- [OPA Gatekeeper Policy Engine](https://open-policy-agent.github.io/gatekeeper/)
- [Istio Service Mesh Security](https://istio.io/latest/docs/concepts/security/)

### Training & Certification
- **Certified Kubernetes Security Specialist (CKS)**
- **Kubernetes Security Best Practices Training**
- **Cloud Native Security Fundamentals**

---

## 🤝 Contributing

To contribute to Kubernetes security configurations:

1. **Test** configurations in development environment
2. **Validate** against security benchmarks
3. **Document** security implications
4. **Review** with security team
5. **Submit** pull request with security impact assessment

## 📞 Support

For security-related questions or incidents:

- **Security Team**: security@company.com
- **Emergency Hotline**: +1-800-SECURITY
- **Incident Response**: https://company.com/incident-response
- **Security Documentation**: https://docs.company.com/security/kubernetes

---

**Remember**: Security is a shared responsibility. Every team member plays a crucial role in maintaining a secure Kubernetes environment! 🛡️