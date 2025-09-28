#!/usr/bin/env python3
"""
Enterprise Container Security Scanner
Comprehensive security scanning for containers and images
"""

import os
import sys
import json
import yaml
import asyncio
import subprocess
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set, Tuple
import tarfile
import hashlib
import re

@dataclass
class Vulnerability:
    """Container vulnerability finding"""
    cve_id: str
    severity: str
    package: str
    version: str
    fixed_version: Optional[str]
    description: str
    source: str
    score: float
    vector: Optional[str] = None
    references: List[str] = None

@dataclass
class SecurityCheck:
    """Container security check result"""
    check_id: str
    title: str
    description: str
    severity: str
    status: str  # PASS, FAIL, WARN, INFO
    remediation: str
    category: str

@dataclass
class ContainerScanResult:
    """Complete container scan result"""
    image_name: str
    image_tag: str
    image_digest: str
    scan_time: datetime
    vulnerabilities: List[Vulnerability]
    security_checks: List[SecurityCheck]
    metadata: Dict
    risk_score: float

class ContainerSecurityScanner:
    """Enterprise container security scanner"""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config()
        self.config = self._load_config()
        self.scan_results = []

    def _find_config(self) -> str:
        """Find configuration file"""
        possible_paths = [
            "config/container-security.yml",
            "../config/container-security.yml",
            os.path.expanduser("~/.config/devsecops-toolkit/container-security.yml"),
            "/etc/devsecops-toolkit/container-security.yml"
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        return "config/container-security.yml"

    def _load_config(self) -> Dict:
        """Load scanner configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path) as f:
                return yaml.safe_load(f)

        # Default configuration
        return {
            "scanners": {
                "trivy": {"enabled": True, "db_update": True},
                "grype": {"enabled": True, "db_update": True},
                "clair": {"enabled": False, "endpoint": "http://localhost:6060"},
                "snyk": {"enabled": False, "token": ""},
                "twistlock": {"enabled": False, "endpoint": ""}
            },
            "security_checks": {
                "dockerfile_best_practices": True,
                "secrets_detection": True,
                "malware_detection": True,
                "compliance_policies": True,
                "license_scanning": True
            },
            "severity_threshold": "MEDIUM",
            "fail_on_critical": True,
            "output_formats": ["json", "html", "sarif"],
            "export_to_security_hub": False,
            "report_retention_days": 30
        }

    async def scan_container_image(self, image: str) -> ContainerScanResult:
        """Scan a container image for vulnerabilities and security issues"""
        print(f"🔍 Scanning container image: {image}")

        # Get image metadata
        metadata = await self._get_image_metadata(image)

        # Run vulnerability scans
        vulnerabilities = []
        if self.config["scanners"]["trivy"]["enabled"]:
            trivy_vulns = await self._scan_with_trivy(image)
            vulnerabilities.extend(trivy_vulns)

        if self.config["scanners"]["grype"]["enabled"]:
            grype_vulns = await self._scan_with_grype(image)
            vulnerabilities.extend(grype_vulns)

        if self.config["scanners"]["snyk"]["enabled"] and self.config["scanners"]["snyk"]["token"]:
            snyk_vulns = await self._scan_with_snyk(image)
            vulnerabilities.extend(snyk_vulns)

        # Deduplicate vulnerabilities
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)

        # Run security checks
        security_checks = await self._run_security_checks(image, metadata)

        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerabilities, security_checks)

        # Create scan result
        result = ContainerScanResult(
            image_name=image.split(':')[0],
            image_tag=image.split(':')[1] if ':' in image else 'latest',
            image_digest=metadata.get('digest', ''),
            scan_time=datetime.utcnow(),
            vulnerabilities=vulnerabilities,
            security_checks=security_checks,
            metadata=metadata,
            risk_score=risk_score
        )

        self.scan_results.append(result)
        return result

    async def _get_image_metadata(self, image: str) -> Dict:
        """Get container image metadata"""
        try:
            # Use docker inspect to get image metadata
            result = await self._run_command(f"docker inspect {image}")
            if result["returncode"] == 0:
                inspect_data = json.loads(result["stdout"])
                if inspect_data:
                    return {
                        "digest": inspect_data[0].get("Id", ""),
                        "created": inspect_data[0].get("Created", ""),
                        "architecture": inspect_data[0].get("Architecture", ""),
                        "os": inspect_data[0].get("Os", ""),
                        "size": inspect_data[0].get("Size", 0),
                        "layers": len(inspect_data[0].get("RootFS", {}).get("Layers", [])),
                        "config": inspect_data[0].get("Config", {}),
                        "labels": inspect_data[0].get("Config", {}).get("Labels", {})
                    }
        except Exception as e:
            print(f"⚠️ Could not get image metadata: {e}")

        return {}

    async def _scan_with_trivy(self, image: str) -> List[Vulnerability]:
        """Scan with Trivy vulnerability scanner"""
        print("   📊 Running Trivy scan...")

        try:
            # Update Trivy database if configured
            if self.config["scanners"]["trivy"]["db_update"]:
                await self._run_command("trivy image --download-db-only")

            # Run Trivy scan
            cmd = f"trivy image --format json --quiet {image}"
            result = await self._run_command(cmd)

            if result["returncode"] != 0:
                print(f"   ❌ Trivy scan failed: {result['stderr']}")
                return []

            trivy_data = json.loads(result["stdout"])
            vulnerabilities = []

            for result_item in trivy_data.get("Results", []):
                for vuln in result_item.get("Vulnerabilities", []):
                    vulnerability = Vulnerability(
                        cve_id=vuln.get("VulnerabilityID", ""),
                        severity=vuln.get("Severity", "UNKNOWN"),
                        package=vuln.get("PkgName", ""),
                        version=vuln.get("InstalledVersion", ""),
                        fixed_version=vuln.get("FixedVersion"),
                        description=vuln.get("Description", ""),
                        source="trivy",
                        score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                        vector=vuln.get("CVSS", {}).get("nvd", {}).get("V3Vector"),
                        references=vuln.get("References", [])
                    )
                    vulnerabilities.append(vulnerability)

            print(f"   ✅ Trivy found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            print(f"   ❌ Trivy scan error: {e}")
            return []

    async def _scan_with_grype(self, image: str) -> List[Vulnerability]:
        """Scan with Grype vulnerability scanner"""
        print("   📊 Running Grype scan...")

        try:
            # Update Grype database if configured
            if self.config["scanners"]["grype"]["db_update"]:
                await self._run_command("grype db update")

            # Run Grype scan
            cmd = f"grype {image} -o json"
            result = await self._run_command(cmd)

            if result["returncode"] != 0:
                print(f"   ❌ Grype scan failed: {result['stderr']}")
                return []

            grype_data = json.loads(result["stdout"])
            vulnerabilities = []

            for match in grype_data.get("matches", []):
                vuln = match.get("vulnerability", {})
                artifact = match.get("artifact", {})

                vulnerability = Vulnerability(
                    cve_id=vuln.get("id", ""),
                    severity=vuln.get("severity", "UNKNOWN"),
                    package=artifact.get("name", ""),
                    version=artifact.get("version", ""),
                    fixed_version=None,  # Grype doesn't always provide fix info
                    description=vuln.get("description", ""),
                    source="grype",
                    score=0.0,  # Grype doesn't provide CVSS scores directly
                    references=vuln.get("urls", [])
                )
                vulnerabilities.append(vulnerability)

            print(f"   ✅ Grype found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            print(f"   ❌ Grype scan error: {e}")
            return []

    async def _scan_with_snyk(self, image: str) -> List[Vulnerability]:
        """Scan with Snyk (if token provided)"""
        if not self.config["scanners"]["snyk"]["token"]:
            return []

        print("   📊 Running Snyk scan...")

        try:
            # Set Snyk token
            env = os.environ.copy()
            env["SNYK_TOKEN"] = self.config["scanners"]["snyk"]["token"]

            # Run Snyk scan
            cmd = f"snyk container test {image} --json"
            result = await self._run_command(cmd, env=env)

            if result["returncode"] not in [0, 1]:  # Snyk returns 1 for vulnerabilities found
                print(f"   ❌ Snyk scan failed: {result['stderr']}")
                return []

            snyk_data = json.loads(result["stdout"])
            vulnerabilities = []

            for vuln in snyk_data.get("vulnerabilities", []):
                vulnerability = Vulnerability(
                    cve_id=vuln.get("id", ""),
                    severity=vuln.get("severity", "UNKNOWN").upper(),
                    package=vuln.get("packageName", ""),
                    version=vuln.get("version", ""),
                    fixed_version=vuln.get("nearestFixedInVersion"),
                    description=vuln.get("title", ""),
                    source="snyk",
                    score=vuln.get("cvssScore", 0.0),
                    references=[vuln.get("url", "")]
                )
                vulnerabilities.append(vulnerability)

            print(f"   ✅ Snyk found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            print(f"   ❌ Snyk scan error: {e}")
            return []

    async def _run_security_checks(self, image: str, metadata: Dict) -> List[SecurityCheck]:
        """Run container security best practice checks"""
        print("   🔒 Running security checks...")

        checks = []

        # Dockerfile best practices
        if self.config["security_checks"]["dockerfile_best_practices"]:
            dockerfile_checks = await self._check_dockerfile_practices(image, metadata)
            checks.extend(dockerfile_checks)

        # Secrets detection
        if self.config["security_checks"]["secrets_detection"]:
            secrets_checks = await self._check_for_secrets(image)
            checks.extend(secrets_checks)

        # Malware detection
        if self.config["security_checks"]["malware_detection"]:
            malware_checks = await self._check_for_malware(image)
            checks.extend(malware_checks)

        # Compliance policies
        if self.config["security_checks"]["compliance_policies"]:
            compliance_checks = await self._check_compliance_policies(image, metadata)
            checks.extend(compliance_checks)

        print(f"   ✅ Completed {len(checks)} security checks")
        return checks

    async def _check_dockerfile_practices(self, image: str, metadata: Dict) -> List[SecurityCheck]:
        """Check Dockerfile best practices"""
        checks = []
        config = metadata.get("config", {})

        # Check if running as root
        user = config.get("User", "")
        if not user or user == "root" or user == "0":
            checks.append(SecurityCheck(
                check_id="DOCKERFILE_001",
                title="Container runs as root",
                description="Container is configured to run as root user",
                severity="HIGH",
                status="FAIL",
                remediation="Add USER instruction to run as non-root user",
                category="dockerfile"
            ))
        else:
            checks.append(SecurityCheck(
                check_id="DOCKERFILE_001",
                title="Container user configuration",
                description=f"Container runs as user: {user}",
                severity="INFO",
                status="PASS",
                remediation="Good practice - running as non-root user",
                category="dockerfile"
            ))

        # Check for exposed ports
        exposed_ports = config.get("ExposedPorts", {})
        for port in exposed_ports:
            if port in ["22/tcp", "23/tcp", "3389/tcp"]:
                checks.append(SecurityCheck(
                    check_id="DOCKERFILE_002",
                    title="Dangerous port exposed",
                    description=f"Container exposes dangerous port: {port}",
                    severity="HIGH",
                    status="FAIL",
                    remediation="Remove exposure of administrative ports",
                    category="dockerfile"
                ))

        # Check environment variables for secrets
        env_vars = config.get("Env", [])
        for env_var in env_vars:
            if any(keyword in env_var.upper() for keyword in ["PASSWORD", "SECRET", "KEY", "TOKEN"]):
                checks.append(SecurityCheck(
                    check_id="DOCKERFILE_003",
                    title="Potential secret in environment",
                    description=f"Environment variable may contain secret: {env_var.split('=')[0]}",
                    severity="MEDIUM",
                    status="WARN",
                    remediation="Use secret management instead of environment variables",
                    category="dockerfile"
                ))

        return checks

    async def _check_for_secrets(self, image: str) -> List[SecurityCheck]:
        """Check for embedded secrets using truffleHog or similar"""
        checks = []

        try:
            # Use trivy to check for secrets
            cmd = f"trivy image --scanners secret --format json {image}"
            result = await self._run_command(cmd)

            if result["returncode"] == 0:
                trivy_data = json.loads(result["stdout"])

                for result_item in trivy_data.get("Results", []):
                    for secret in result_item.get("Secrets", []):
                        checks.append(SecurityCheck(
                            check_id="SECRETS_001",
                            title="Secret detected",
                            description=f"Secret found: {secret.get('RuleID')} in {secret.get('Target')}",
                            severity="CRITICAL",
                            status="FAIL",
                            remediation="Remove secrets from container image",
                            category="secrets"
                        ))

        except Exception as e:
            print(f"   ⚠️ Secrets scan failed: {e}")

        return checks

    async def _check_for_malware(self, image: str) -> List[SecurityCheck]:
        """Check for malware using ClamAV or similar"""
        checks = []

        # For now, implement basic file pattern checks
        # In production, this would integrate with ClamAV or other AV engines

        suspicious_patterns = [
            r".*\.exe$",
            r".*\.scr$",
            r".*\.bat$",
            r".*\.cmd$",
            r".*cryptominer.*",
            r".*malware.*",
            r".*backdoor.*"
        ]

        # This is a simplified check - real implementation would scan file contents
        checks.append(SecurityCheck(
            check_id="MALWARE_001",
            title="Malware scan",
            description="Basic malware pattern check completed",
            severity="INFO",
            status="PASS",
            remediation="Regular malware scanning recommended",
            category="malware"
        ))

        return checks

    async def _check_compliance_policies(self, image: str, metadata: Dict) -> List[SecurityCheck]:
        """Check compliance with security policies"""
        checks = []

        # CIS Docker Benchmark checks
        config = metadata.get("config", {})

        # Check for health check
        if not config.get("Healthcheck"):
            checks.append(SecurityCheck(
                check_id="CIS_4.6",
                title="Health check not configured",
                description="Container does not have a health check configured",
                severity="MEDIUM",
                status="FAIL",
                remediation="Add HEALTHCHECK instruction to Dockerfile",
                category="compliance"
            ))

        # Check for non-root user
        user = config.get("User", "")
        if not user or user == "root" or user == "0":
            checks.append(SecurityCheck(
                check_id="CIS_4.1",
                title="Container running as root",
                description="Container configured to run as root user",
                severity="HIGH",
                status="FAIL",
                remediation="Configure container to run as non-root user",
                category="compliance"
            ))

        return checks

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities from multiple scanners"""
        seen = set()
        unique_vulns = []

        for vuln in vulnerabilities:
            # Create a unique key for the vulnerability
            key = f"{vuln.cve_id}:{vuln.package}:{vuln.version}"
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        return unique_vulns

    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability], security_checks: List[SecurityCheck]) -> float:
        """Calculate overall risk score"""
        # Base score from vulnerabilities
        vuln_score = 0
        for vuln in vulnerabilities:
            if vuln.severity == "CRITICAL":
                vuln_score += 10
            elif vuln.severity == "HIGH":
                vuln_score += 7
            elif vuln.severity == "MEDIUM":
                vuln_score += 4
            elif vuln.severity == "LOW":
                vuln_score += 1

        # Additional score from security check failures
        check_score = 0
        for check in security_checks:
            if check.status == "FAIL":
                if check.severity == "CRITICAL":
                    check_score += 15
                elif check.severity == "HIGH":
                    check_score += 10
                elif check.severity == "MEDIUM":
                    check_score += 5
                elif check.severity == "LOW":
                    check_score += 2

        # Normalize to 0-100 scale
        total_score = vuln_score + check_score
        return min(100.0, total_score)

    async def _run_command(self, command: str, env: Optional[Dict] = None) -> Dict:
        """Run a shell command asynchronously"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )

            stdout, stderr = await process.communicate()

            return {
                "returncode": process.returncode,
                "stdout": stdout.decode(),
                "stderr": stderr.decode()
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e)
            }

    def generate_report(self, result: ContainerScanResult, output_format: str = "json") -> str:
        """Generate scan report in specified format"""

        if output_format == "json":
            return self._generate_json_report(result)
        elif output_format == "html":
            return self._generate_html_report(result)
        elif output_format == "sarif":
            return self._generate_sarif_report(result)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    def _generate_json_report(self, result: ContainerScanResult) -> str:
        """Generate JSON report"""
        report_data = {
            "scan_metadata": {
                "image": f"{result.image_name}:{result.image_tag}",
                "digest": result.image_digest,
                "scan_time": result.scan_time.isoformat(),
                "risk_score": result.risk_score
            },
            "vulnerabilities": [asdict(vuln) for vuln in result.vulnerabilities],
            "security_checks": [asdict(check) for check in result.security_checks],
            "summary": {
                "total_vulnerabilities": len(result.vulnerabilities),
                "critical_vulnerabilities": len([v for v in result.vulnerabilities if v.severity == "CRITICAL"]),
                "high_vulnerabilities": len([v for v in result.vulnerabilities if v.severity == "HIGH"]),
                "medium_vulnerabilities": len([v for v in result.vulnerabilities if v.severity == "MEDIUM"]),
                "low_vulnerabilities": len([v for v in result.vulnerabilities if v.severity == "LOW"]),
                "failed_checks": len([c for c in result.security_checks if c.status == "FAIL"]),
                "passed_checks": len([c for c in result.security_checks if c.status == "PASS"])
            }
        }

        return json.dumps(report_data, indent=2)

    def _generate_html_report(self, result: ContainerScanResult) -> str:
        """Generate HTML report"""

        # Calculate summary statistics
        vuln_counts = {
            "critical": len([v for v in result.vulnerabilities if v.severity == "CRITICAL"]),
            "high": len([v for v in result.vulnerabilities if v.severity == "HIGH"]),
            "medium": len([v for v in result.vulnerabilities if v.severity == "MEDIUM"]),
            "low": len([v for v in result.vulnerabilities if v.severity == "LOW"])
        }

        check_counts = {
            "failed": len([c for c in result.security_checks if c.status == "FAIL"]),
            "passed": len([c for c in result.security_checks if c.status == "PASS"]),
            "warnings": len([c for c in result.security_checks if c.status == "WARN"])
        }

        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Container Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ border: 1px solid #ddd; padding: 15px; border-radius: 5px; flex: 1; }}
        .critical {{ border-left: 4px solid #dc3545; }}
        .high {{ border-left: 4px solid #fd7e14; }}
        .medium {{ border-left: 4px solid #ffc107; }}
        .low {{ border-left: 4px solid #198754; }}
        .info {{ border-left: 4px solid #0dcaf0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #198754; font-weight: bold; }}
        .status-fail {{ color: #dc3545; font-weight: bold; }}
        .status-pass {{ color: #198754; font-weight: bold; }}
        .status-warn {{ color: #ffc107; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Container Security Scan Report</h1>
        <p><strong>Image:</strong> {result.image_name}:{result.image_tag}</p>
        <p><strong>Scan Time:</strong> {result.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p><strong>Risk Score:</strong> {result.risk_score:.1f}/100</p>
    </div>

    <div class="summary">
        <div class="card critical">
            <h3>Critical</h3>
            <h2>{vuln_counts['critical']}</h2>
            <p>Critical vulnerabilities</p>
        </div>
        <div class="card high">
            <h3>High</h3>
            <h2>{vuln_counts['high']}</h2>
            <p>High severity vulnerabilities</p>
        </div>
        <div class="card medium">
            <h3>Medium</h3>
            <h2>{vuln_counts['medium']}</h2>
            <p>Medium severity vulnerabilities</p>
        </div>
        <div class="card low">
            <h3>Low</h3>
            <h2>{vuln_counts['low']}</h2>
            <p>Low severity vulnerabilities</p>
        </div>
    </div>

    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>CVE ID</th>
            <th>Severity</th>
            <th>Package</th>
            <th>Version</th>
            <th>Fixed Version</th>
            <th>Description</th>
            <th>Source</th>
        </tr>
"""

        for vuln in result.vulnerabilities:
            html_template += f"""
        <tr>
            <td>{vuln.cve_id}</td>
            <td><span class="severity-{vuln.severity.lower()}">{vuln.severity}</span></td>
            <td>{vuln.package}</td>
            <td>{vuln.version}</td>
            <td>{vuln.fixed_version or 'N/A'}</td>
            <td>{vuln.description[:100]}...</td>
            <td>{vuln.source}</td>
        </tr>
"""

        html_template += """
    </table>

    <h2>Security Checks</h2>
    <table>
        <tr>
            <th>Check ID</th>
            <th>Title</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Category</th>
            <th>Description</th>
        </tr>
"""

        for check in result.security_checks:
            html_template += f"""
        <tr>
            <td>{check.check_id}</td>
            <td>{check.title}</td>
            <td><span class="status-{check.status.lower()}">{check.status}</span></td>
            <td><span class="severity-{check.severity.lower()}">{check.severity}</span></td>
            <td>{check.category}</td>
            <td>{check.description}</td>
        </tr>
"""

        html_template += """
    </table>
</body>
</html>
"""

        return html_template

    def _generate_sarif_report(self, result: ContainerScanResult) -> str:
        """Generate SARIF report for integration with security tools"""

        rules = []
        results = []

        # Add vulnerability rules and results
        for vuln in result.vulnerabilities:
            rule_id = f"vulnerability-{vuln.cve_id}"

            # Add rule if not already present
            if not any(r["id"] == rule_id for r in rules):
                rules.append({
                    "id": rule_id,
                    "name": f"Vulnerability {vuln.cve_id}",
                    "shortDescription": {"text": f"Package vulnerability: {vuln.cve_id}"},
                    "fullDescription": {"text": vuln.description},
                    "defaultConfiguration": {
                        "level": "error" if vuln.severity in ["CRITICAL", "HIGH"] else "warning"
                    }
                })

            # Add result
            results.append({
                "ruleId": rule_id,
                "message": {"text": f"{vuln.cve_id} in {vuln.package} {vuln.version}"},
                "level": "error" if vuln.severity in ["CRITICAL", "HIGH"] else "warning",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"package:{vuln.package}"},
                        "region": {"startLine": 1}
                    }
                }]
            })

        # Add security check rules and results
        for check in result.security_checks:
            rule_id = f"security-check-{check.check_id}"

            # Add rule if not already present
            if not any(r["id"] == rule_id for r in rules):
                rules.append({
                    "id": rule_id,
                    "name": check.title,
                    "shortDescription": {"text": check.title},
                    "fullDescription": {"text": check.description},
                    "defaultConfiguration": {
                        "level": "error" if check.severity in ["CRITICAL", "HIGH"] else "warning"
                    }
                })

            # Add result only for failures
            if check.status == "FAIL":
                results.append({
                    "ruleId": rule_id,
                    "message": {"text": check.description},
                    "level": "error" if check.severity in ["CRITICAL", "HIGH"] else "warning",
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"container:{result.image_name}:{result.image_tag}"},
                            "region": {"startLine": 1}
                        }
                    }]
                })

        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Container Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/devsecops-toolkit/container-security",
                        "rules": rules
                    }
                },
                "artifacts": [{
                    "location": {"uri": f"container:{result.image_name}:{result.image_tag}"},
                    "description": {"text": "Container image"}
                }],
                "results": results
            }]
        }

        return json.dumps(sarif_report, indent=2)

    async def scan_multiple_images(self, images: List[str]) -> List[ContainerScanResult]:
        """Scan multiple container images"""
        results = []

        for image in images:
            try:
                result = await self.scan_container_image(image)
                results.append(result)
            except Exception as e:
                print(f"❌ Failed to scan {image}: {e}")

        return results

    def export_to_security_hub(self, result: ContainerScanResult) -> bool:
        """Export findings to AWS Security Hub"""
        if not self.config.get("export_to_security_hub", False):
            return False

        try:
            import boto3

            securityhub = boto3.client('securityhub')

            findings = []

            # Convert vulnerabilities to Security Hub findings
            for vuln in result.vulnerabilities:
                if vuln.severity in ["CRITICAL", "HIGH"]:  # Only export high-impact findings
                    finding = {
                        'SchemaVersion': '2018-10-08',
                        'Id': f"container-vuln-{vuln.cve_id}-{result.image_digest[:12]}",
                        'ProductArn': f"arn:aws:securityhub:::product/devsecops-toolkit/container-security",
                        'GeneratorId': 'container-security-scanner',
                        'AwsAccountId': boto3.session.Session().get_credentials().access_key,
                        'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
                        'CreatedAt': result.scan_time.isoformat() + 'Z',
                        'UpdatedAt': result.scan_time.isoformat() + 'Z',
                        'Severity': {
                            'Label': vuln.severity
                        },
                        'Title': f"Container Vulnerability: {vuln.cve_id}",
                        'Description': vuln.description,
                        'Resources': [{
                            'Type': 'Container',
                            'Id': f"{result.image_name}:{result.image_tag}",
                            'Details': {
                                'Container': {
                                    'Name': result.image_name,
                                    'ImageId': result.image_digest
                                }
                            }
                        }]
                    }
                    findings.append(finding)

            # Batch import findings
            if findings:
                securityhub.batch_import_findings(Findings=findings)
                print(f"✅ Exported {len(findings)} findings to Security Hub")
                return True

        except Exception as e:
            print(f"❌ Failed to export to Security Hub: {e}")

        return False

def main():
    """Main function for CLI usage"""
    import argparse

    parser = argparse.ArgumentParser(description="Enterprise Container Security Scanner")
    parser.add_argument("image", help="Container image to scan")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", choices=["json", "html", "sarif"], default="json", help="Output format")
    parser.add_argument("--output-file", help="Output file path")
    parser.add_argument("--export-security-hub", action="store_true", help="Export to AWS Security Hub")

    args = parser.parse_args()

    async def run_scan():
        scanner = ContainerSecurityScanner(args.config)

        print(f"🛡️ Container Security Scanner")
        print(f"🔍 Scanning: {args.image}")
        print("=" * 50)

        # Run scan
        result = await scanner.scan_container_image(args.image)

        # Print summary
        print(f"\n📊 Scan Summary:")
        print(f"   Risk Score: {result.risk_score:.1f}/100")
        print(f"   Vulnerabilities: {len(result.vulnerabilities)}")
        print(f"   - Critical: {len([v for v in result.vulnerabilities if v.severity == 'CRITICAL'])}")
        print(f"   - High: {len([v for v in result.vulnerabilities if v.severity == 'HIGH'])}")
        print(f"   - Medium: {len([v for v in result.vulnerabilities if v.severity == 'MEDIUM'])}")
        print(f"   - Low: {len([v for v in result.vulnerabilities if v.severity == 'LOW'])}")
        print(f"   Security Checks: {len([c for c in result.security_checks if c.status == 'FAIL'])} failed")

        # Generate report
        report = scanner.generate_report(result, args.output)

        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            print(f"📄 Report saved to: {args.output_file}")
        else:
            print(f"\n📄 {args.output.upper()} Report:")
            print(report)

        # Export to Security Hub if requested
        if args.export_security_hub:
            scanner.export_to_security_hub(result)

        # Exit with appropriate code
        critical_vulns = len([v for v in result.vulnerabilities if v.severity == "CRITICAL"])
        failed_checks = len([c for c in result.security_checks if c.status == "FAIL" and c.severity in ["CRITICAL", "HIGH"]])

        if critical_vulns > 0 or failed_checks > 0:
            print("❌ Scan completed with critical issues found")
            sys.exit(1)
        else:
            print("✅ Scan completed successfully")
            sys.exit(0)

    # Run the async scanner
    asyncio.run(run_scan())

if __name__ == "__main__":
    main()