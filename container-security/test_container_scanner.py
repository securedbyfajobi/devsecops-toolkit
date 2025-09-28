#!/usr/bin/env python3
"""
Test suite for Container Security Scanner
Validates functionality without requiring external scanner binaries
"""

import os
import sys
import json
import asyncio
import tempfile
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from container_scanner import (
    ContainerSecurityScanner,
    Vulnerability,
    SecurityCheck,
    ContainerScanResult
)

class TestContainerSecurityScanner:
    """Test suite for the container scanner"""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance for testing"""
        return ContainerSecurityScanner()

    @pytest.fixture
    def mock_vulnerabilities(self):
        """Mock vulnerability data"""
        return [
            Vulnerability(
                cve_id="CVE-2023-0001",
                severity="CRITICAL",
                package="openssl",
                version="1.1.1",
                fixed_version="1.1.1n",
                description="Critical vulnerability in OpenSSL",
                source="trivy",
                score=9.8,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0001"]
            ),
            Vulnerability(
                cve_id="CVE-2023-0002",
                severity="HIGH",
                package="curl",
                version="7.68.0",
                fixed_version="7.68.1",
                description="High severity vulnerability in curl",
                source="grype",
                score=7.5,
                references=["https://curl.se/docs/security.html"]
            )
        ]

    @pytest.fixture
    def mock_security_checks(self):
        """Mock security check data"""
        return [
            SecurityCheck(
                check_id="DOCKERFILE_001",
                title="Container runs as root",
                description="Container is configured to run as root user",
                severity="HIGH",
                status="FAIL",
                remediation="Add USER instruction to run as non-root user",
                category="dockerfile"
            ),
            SecurityCheck(
                check_id="SECRETS_001",
                title="No secrets detected",
                description="No hardcoded secrets found in image",
                severity="INFO",
                status="PASS",
                remediation="Continue following secure practices",
                category="secrets"
            )
        ]

    def test_scanner_initialization(self):
        """Test scanner initialization"""
        scanner = ContainerSecurityScanner()
        assert scanner.config is not None
        assert "scanners" in scanner.config
        assert "security_checks" in scanner.config

    def test_config_loading(self):
        """Test configuration loading"""
        scanner = ContainerSecurityScanner()
        config = scanner.config

        # Check default configuration structure
        assert config["scanners"]["trivy"]["enabled"] is True
        assert config["scanners"]["grype"]["enabled"] is True
        assert config["security_checks"]["dockerfile_best_practices"] is True
        assert config["severity_threshold"] == "MEDIUM"

    @pytest.mark.asyncio
    async def test_get_image_metadata(self):
        """Test image metadata extraction"""
        scanner = ContainerSecurityScanner()

        # Mock docker inspect output
        mock_inspect_data = [{
            "Id": "sha256:abc123",
            "Created": "2023-01-01T00:00:00Z",
            "Architecture": "amd64",
            "Os": "linux",
            "Size": 1000000,
            "RootFS": {"Layers": ["layer1", "layer2"]},
            "Config": {
                "User": "nonroot",
                "ExposedPorts": {"80/tcp": {}},
                "Env": ["PATH=/usr/bin"],
                "Labels": {"version": "1.0"}
            }
        }]

        with patch.object(scanner, '_run_command') as mock_run:
            mock_run.return_value = {
                "returncode": 0,
                "stdout": json.dumps(mock_inspect_data),
                "stderr": ""
            }

            metadata = await scanner._get_image_metadata("test:latest")

            assert metadata["digest"] == "sha256:abc123"
            assert metadata["architecture"] == "amd64"
            assert metadata["os"] == "linux"
            assert metadata["layers"] == 2
            assert metadata["config"]["User"] == "nonroot"

    @pytest.mark.asyncio
    async def test_scan_with_trivy_mock(self):
        """Test Trivy scanning with mocked data"""
        scanner = ContainerSecurityScanner()

        # Mock Trivy output
        mock_trivy_data = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-0001",
                    "Severity": "CRITICAL",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1",
                    "FixedVersion": "1.1.1n",
                    "Description": "Critical vulnerability",
                    "CVSS": {
                        "nvd": {
                            "V3Score": 9.8,
                            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
                    },
                    "References": ["https://example.com/cve"]
                }]
            }]
        }

        with patch.object(scanner, '_run_command') as mock_run:
            mock_run.return_value = {
                "returncode": 0,
                "stdout": json.dumps(mock_trivy_data),
                "stderr": ""
            }

            vulnerabilities = await scanner._scan_with_trivy("test:latest")

            assert len(vulnerabilities) == 1
            assert vulnerabilities[0].cve_id == "CVE-2023-0001"
            assert vulnerabilities[0].severity == "CRITICAL"
            assert vulnerabilities[0].package == "openssl"
            assert vulnerabilities[0].source == "trivy"

    @pytest.mark.asyncio
    async def test_dockerfile_best_practices_check(self):
        """Test Dockerfile best practices checking"""
        scanner = ContainerSecurityScanner()

        # Test root user detection
        metadata_root = {
            "config": {
                "User": "",  # Empty user means root
                "ExposedPorts": {"22/tcp": {}},  # SSH port
                "Env": ["PASSWORD=secret123"]  # Secret in env
            }
        }

        checks = await scanner._check_dockerfile_practices("test:latest", metadata_root)

        # Should have failures for root user, dangerous port, and secret in env
        root_check = next((c for c in checks if c.check_id == "DOCKERFILE_001"), None)
        assert root_check is not None
        assert root_check.status == "FAIL"
        assert root_check.severity == "HIGH"

        # Test non-root user
        metadata_nonroot = {
            "config": {
                "User": "nonroot",
                "ExposedPorts": {"80/tcp": {}},
                "Env": ["PATH=/usr/bin"]
            }
        }

        checks = await scanner._check_dockerfile_practices("test:latest", metadata_nonroot)
        root_check = next((c for c in checks if c.check_id == "DOCKERFILE_001"), None)
        assert root_check is not None
        assert root_check.status == "PASS"

    @pytest.mark.asyncio
    async def test_secrets_detection(self):
        """Test secrets detection functionality"""
        scanner = ContainerSecurityScanner()

        # Mock Trivy secrets scan output
        mock_secrets_data = {
            "Results": [{
                "Secrets": [{
                    "RuleID": "aws-access-key-id",
                    "Target": "/app/config.json",
                    "Title": "AWS Access Key ID",
                    "Match": "AKIA1234567890123456"
                }]
            }]
        }

        with patch.object(scanner, '_run_command') as mock_run:
            mock_run.return_value = {
                "returncode": 0,
                "stdout": json.dumps(mock_secrets_data),
                "stderr": ""
            }

            checks = await scanner._check_for_secrets("test:latest")

            assert len(checks) == 1
            assert checks[0].check_id == "SECRETS_001"
            assert checks[0].severity == "CRITICAL"
            assert checks[0].status == "FAIL"
            assert "aws-access-key-id" in checks[0].description

    def test_vulnerability_deduplication(self):
        """Test vulnerability deduplication"""
        scanner = ContainerSecurityScanner()

        # Create duplicate vulnerabilities from different sources
        vulns = [
            Vulnerability("CVE-2023-0001", "HIGH", "pkg1", "1.0", "1.1", "desc", "trivy", 7.0),
            Vulnerability("CVE-2023-0001", "HIGH", "pkg1", "1.0", "1.1", "desc", "grype", 7.0),  # Duplicate
            Vulnerability("CVE-2023-0002", "MEDIUM", "pkg2", "2.0", "2.1", "desc", "trivy", 5.0)
        ]

        unique_vulns = scanner._deduplicate_vulnerabilities(vulns)

        assert len(unique_vulns) == 2
        assert unique_vulns[0].cve_id == "CVE-2023-0001"
        assert unique_vulns[1].cve_id == "CVE-2023-0002"

    def test_risk_score_calculation(self, mock_vulnerabilities, mock_security_checks):
        """Test risk score calculation"""
        scanner = ContainerSecurityScanner()

        risk_score = scanner._calculate_risk_score(mock_vulnerabilities, mock_security_checks)

        # Expected: 1 CRITICAL (10) + 1 HIGH (7) + 1 HIGH FAIL (10) = 27
        assert risk_score == 27.0

    def test_json_report_generation(self, mock_vulnerabilities, mock_security_checks):
        """Test JSON report generation"""
        scanner = ContainerSecurityScanner()

        result = ContainerScanResult(
            image_name="test",
            image_tag="latest",
            image_digest="sha256:abc123",
            scan_time=datetime.utcnow(),
            vulnerabilities=mock_vulnerabilities,
            security_checks=mock_security_checks,
            metadata={},
            risk_score=27.0
        )

        report = scanner.generate_report(result, "json")
        report_data = json.loads(report)

        assert report_data["scan_metadata"]["image"] == "test:latest"
        assert report_data["scan_metadata"]["risk_score"] == 27.0
        assert len(report_data["vulnerabilities"]) == 2
        assert len(report_data["security_checks"]) == 2
        assert report_data["summary"]["critical_vulnerabilities"] == 1
        assert report_data["summary"]["high_vulnerabilities"] == 1

    def test_html_report_generation(self, mock_vulnerabilities, mock_security_checks):
        """Test HTML report generation"""
        scanner = ContainerSecurityScanner()

        result = ContainerScanResult(
            image_name="test",
            image_tag="latest",
            image_digest="sha256:abc123",
            scan_time=datetime.utcnow(),
            vulnerabilities=mock_vulnerabilities,
            security_checks=mock_security_checks,
            metadata={},
            risk_score=27.0
        )

        report = scanner.generate_report(result, "html")

        assert "Container Security Scan Report" in report
        assert "test:latest" in report
        assert "CVE-2023-0001" in report
        assert "DOCKERFILE_001" in report
        assert "Risk Score: 27.0" in report

    def test_sarif_report_generation(self, mock_vulnerabilities, mock_security_checks):
        """Test SARIF report generation"""
        scanner = ContainerSecurityScanner()

        result = ContainerScanResult(
            image_name="test",
            image_tag="latest",
            image_digest="sha256:abc123",
            scan_time=datetime.utcnow(),
            vulnerabilities=mock_vulnerabilities,
            security_checks=mock_security_checks,
            metadata={},
            risk_score=27.0
        )

        report = scanner.generate_report(result, "sarif")
        sarif_data = json.loads(report)

        assert sarif_data["version"] == "2.1.0"
        assert len(sarif_data["runs"]) == 1
        assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "Container Security Scanner"
        assert len(sarif_data["runs"][0]["results"]) >= 2  # Vulnerabilities + failed checks

    @pytest.mark.asyncio
    async def test_compliance_policies_check(self):
        """Test compliance policies checking"""
        scanner = ContainerSecurityScanner()

        # Test metadata that violates CIS benchmarks
        metadata = {
            "config": {
                "User": "",  # Root user - CIS violation
                "Healthcheck": None  # No health check - CIS violation
            }
        }

        checks = await scanner._check_compliance_policies("test:latest", metadata)

        # Should have CIS violations
        cis_checks = [c for c in checks if c.category == "compliance"]
        assert len(cis_checks) >= 2

        root_check = next((c for c in cis_checks if c.check_id == "CIS_4.1"), None)
        health_check = next((c for c in cis_checks if c.check_id == "CIS_4.6"), None)

        assert root_check is not None
        assert root_check.status == "FAIL"
        assert health_check is not None
        assert health_check.status == "FAIL"

    @pytest.mark.asyncio
    async def test_full_scan_workflow(self):
        """Test complete scan workflow with mocked external tools"""
        scanner = ContainerSecurityScanner()

        # Mock all external command calls
        async def mock_run_command(command, env=None):
            if "docker inspect" in command:
                return {
                    "returncode": 0,
                    "stdout": json.dumps([{
                        "Id": "sha256:abc123",
                        "Created": "2023-01-01T00:00:00Z",
                        "Architecture": "amd64",
                        "Os": "linux",
                        "Size": 1000000,
                        "RootFS": {"Layers": ["layer1", "layer2"]},
                        "Config": {
                            "User": "root",
                            "ExposedPorts": {"80/tcp": {}},
                            "Env": ["PATH=/usr/bin"]
                        }
                    }]),
                    "stderr": ""
                }
            elif "trivy" in command and "json" in command:
                return {
                    "returncode": 0,
                    "stdout": json.dumps({
                        "Results": [{
                            "Vulnerabilities": [{
                                "VulnerabilityID": "CVE-2023-0001",
                                "Severity": "HIGH",
                                "PkgName": "testpkg",
                                "InstalledVersion": "1.0",
                                "FixedVersion": "1.1",
                                "Description": "Test vulnerability",
                                "CVSS": {"nvd": {"V3Score": 7.5}},
                                "References": ["https://example.com"]
                            }]
                        }]
                    }),
                    "stderr": ""
                }
            else:
                return {"returncode": 0, "stdout": "", "stderr": ""}

        with patch.object(scanner, '_run_command', side_effect=mock_run_command):
            result = await scanner.scan_container_image("test:latest")

            assert result.image_name == "test"
            assert result.image_tag == "latest"
            assert len(result.vulnerabilities) >= 1
            assert len(result.security_checks) >= 1
            assert result.risk_score > 0

def test_configuration_file_structure():
    """Test that configuration file has proper structure"""
    config_path = Path(__file__).parent / "config" / "container-security.yml"

    if config_path.exists():
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f)

        # Test required sections
        assert "scanners" in config
        assert "security_checks" in config
        assert "severity" in config
        assert "output" in config

        # Test scanner configurations
        assert "trivy" in config["scanners"]
        assert "grype" in config["scanners"]
        assert config["scanners"]["trivy"]["enabled"] is True

def test_requirements_file():
    """Test that requirements file exists and contains necessary packages"""
    req_path = Path(__file__).parent / "requirements.txt"
    assert req_path.exists()

    with open(req_path) as f:
        content = f.read()

    # Check for essential packages
    assert "pyyaml" in content
    assert "asyncio" in content or "aiohttp" in content
    assert "docker" in content
    assert "boto3" in content  # For AWS integration

def run_simple_tests():
    """Run basic tests without pytest dependencies"""
    print("🧪 Container Security Scanner - Simple Test Suite")
    print("=" * 50)

    # Test 1: Basic imports
    print("✅ Testing imports...")
    try:
        from container_scanner import ContainerSecurityScanner, Vulnerability, SecurityCheck
        print("   ✓ All imports successful")
    except Exception as e:
        print(f"   ❌ Import failed: {e}")
        return False

    # Test 2: Scanner initialization
    print("✅ Testing scanner initialization...")
    try:
        scanner = ContainerSecurityScanner()
        assert scanner.config is not None
        print("   ✓ Scanner initialized successfully")
    except Exception as e:
        print(f"   ❌ Scanner initialization failed: {e}")
        return False

    # Test 3: Configuration loading
    print("✅ Testing configuration...")
    try:
        scanner = ContainerSecurityScanner()
        config = scanner.config
        assert "scanners" in config
        assert "security_checks" in config
        print("   ✓ Configuration loaded successfully")
    except Exception as e:
        print(f"   ❌ Configuration test failed: {e}")
        return False

    # Test 4: Data structures
    print("✅ Testing data structures...")
    try:
        vuln = Vulnerability(
            cve_id="CVE-2023-TEST",
            severity="HIGH",
            package="testpkg",
            version="1.0",
            fixed_version="1.1",
            description="Test vulnerability",
            source="test",
            score=7.5
        )
        assert vuln.cve_id == "CVE-2023-TEST"

        check = SecurityCheck(
            check_id="TEST_001",
            title="Test Check",
            description="Test security check",
            severity="MEDIUM",
            status="PASS",
            remediation="No action needed",
            category="test"
        )
        assert check.status == "PASS"
        print("   ✓ Data structures working correctly")
    except Exception as e:
        print(f"   ❌ Data structure test failed: {e}")
        return False

    # Test 5: Risk score calculation
    print("✅ Testing risk score calculation...")
    try:
        scanner = ContainerSecurityScanner()
        vulns = [
            Vulnerability("CVE-1", "CRITICAL", "pkg1", "1.0", "1.1", "desc", "test", 9.0),
            Vulnerability("CVE-2", "HIGH", "pkg2", "2.0", "2.1", "desc", "test", 7.0)
        ]
        checks = [
            SecurityCheck("CHK-1", "Test", "desc", "HIGH", "FAIL", "fix", "test")
        ]
        score = scanner._calculate_risk_score(vulns, checks)
        assert score > 0
        print(f"   ✓ Risk score calculated: {score}")
    except Exception as e:
        print(f"   ❌ Risk score test failed: {e}")
        return False

    # Test 6: Report generation
    print("✅ Testing report generation...")
    try:
        from datetime import datetime
        scanner = ContainerSecurityScanner()

        result = type('MockResult', (), {
            'image_name': 'test',
            'image_tag': 'latest',
            'image_digest': 'sha256:abc123',
            'scan_time': datetime.utcnow(),
            'vulnerabilities': [],
            'security_checks': [],
            'metadata': {},
            'risk_score': 0.0
        })()

        json_report = scanner.generate_report(result, "json")
        assert "scan_metadata" in json_report
        print("   ✓ JSON report generation working")

        html_report = scanner.generate_report(result, "html")
        assert "Container Security Scan Report" in html_report
        print("   ✓ HTML report generation working")
    except Exception as e:
        print(f"   ❌ Report generation test failed: {e}")
        return False

    print("\n🎉 All simple tests passed!")
    print("\n📋 Next Steps:")
    print("1. Install required scanners:")
    print("   - Trivy: https://aquasecurity.github.io/trivy/")
    print("   - Grype: https://github.com/anchore/grype")
    print("2. Install Python dependencies:")
    print("   pip install -r requirements.txt")
    print("3. Run a test scan:")
    print("   python container-scanner.py alpine:latest")

    return True

if __name__ == "__main__":
    # Try to run pytest if available, otherwise run simple tests
    try:
        import pytest
        sys.exit(pytest.main([__file__]))
    except ImportError:
        success = run_simple_tests()
        sys.exit(0 if success else 1)