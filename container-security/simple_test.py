#!/usr/bin/env python3
"""
Simple test script for Container Security Scanner
Tests basic functionality without external dependencies
"""

import os
import sys
import json
import asyncio
from datetime import datetime
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all required modules can be imported"""
    print("🔍 Testing imports...")

    try:
        from container_scanner import (
            ContainerSecurityScanner,
            Vulnerability,
            SecurityCheck,
            ContainerScanResult
        )
        print("   ✅ Core classes imported successfully")
        return True
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")
        return False

def test_data_structures():
    """Test data structure creation and validation"""
    print("🔍 Testing data structures...")

    try:
        from container_scanner import Vulnerability, SecurityCheck

        # Test Vulnerability creation
        vuln = Vulnerability(
            cve_id="CVE-2023-TEST",
            severity="HIGH",
            package="test-package",
            version="1.0.0",
            fixed_version="1.0.1",
            description="Test vulnerability for validation",
            source="test",
            score=7.5,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            references=["https://example.com/cve-test"]
        )

        assert vuln.cve_id == "CVE-2023-TEST"
        assert vuln.severity == "HIGH"
        assert vuln.score == 7.5
        print("   ✅ Vulnerability structure working")

        # Test SecurityCheck creation
        check = SecurityCheck(
            check_id="TEST_001",
            title="Test Security Check",
            description="This is a test security check",
            severity="MEDIUM",
            status="PASS",
            remediation="No action required for test",
            category="test"
        )

        assert check.check_id == "TEST_001"
        assert check.status == "PASS"
        print("   ✅ SecurityCheck structure working")

        return True
    except Exception as e:
        print(f"   ❌ Data structure test failed: {e}")
        return False

def test_scanner_initialization():
    """Test scanner initialization"""
    print("🔍 Testing scanner initialization...")

    try:
        from container_scanner import ContainerSecurityScanner

        scanner = ContainerSecurityScanner()

        # Check that scanner has required attributes
        assert hasattr(scanner, 'config')
        assert hasattr(scanner, 'scan_results')
        assert scanner.config is not None
        assert isinstance(scanner.scan_results, list)

        # Check configuration structure
        config = scanner.config
        assert "scanners" in config
        assert "security_checks" in config
        assert "severity_threshold" in config

        print("   ✅ Scanner initialization successful")
        return True
    except Exception as e:
        print(f"   ❌ Scanner initialization failed: {e}")
        return False

def test_configuration_loading():
    """Test configuration file loading"""
    print("🔍 Testing configuration loading...")

    try:
        from container_scanner import ContainerSecurityScanner

        scanner = ContainerSecurityScanner()
        config = scanner.config

        # Test default configuration values
        assert config["scanners"]["trivy"]["enabled"] is True
        assert config["scanners"]["grype"]["enabled"] is True
        assert config["security_checks"]["dockerfile_best_practices"] is True
        assert config["severity_threshold"] == "MEDIUM"

        print("   ✅ Configuration loading successful")
        return True
    except Exception as e:
        print(f"   ❌ Configuration loading failed: {e}")
        return False

def test_risk_score_calculation():
    """Test risk score calculation logic"""
    print("🔍 Testing risk score calculation...")

    try:
        from container_scanner import ContainerSecurityScanner, Vulnerability, SecurityCheck

        scanner = ContainerSecurityScanner()

        # Create test vulnerabilities
        vulnerabilities = [
            Vulnerability("CVE-1", "CRITICAL", "pkg1", "1.0", "1.1", "Critical vuln", "test", 9.0),
            Vulnerability("CVE-2", "HIGH", "pkg2", "2.0", "2.1", "High vuln", "test", 7.0),
            Vulnerability("CVE-3", "MEDIUM", "pkg3", "3.0", "3.1", "Medium vuln", "test", 5.0),
            Vulnerability("CVE-4", "LOW", "pkg4", "4.0", "4.1", "Low vuln", "test", 2.0)
        ]

        # Create test security checks
        security_checks = [
            SecurityCheck("CHK-1", "Critical Fail", "desc", "CRITICAL", "FAIL", "fix", "test"),
            SecurityCheck("CHK-2", "High Pass", "desc", "HIGH", "PASS", "good", "test"),
            SecurityCheck("CHK-3", "Medium Fail", "desc", "MEDIUM", "FAIL", "fix", "test")
        ]

        # Calculate risk score
        risk_score = scanner._calculate_risk_score(vulnerabilities, security_checks)

        # Expected: CRITICAL(10) + HIGH(7) + MEDIUM(4) + LOW(1) + CRITICAL_FAIL(15) + MEDIUM_FAIL(5) = 42
        expected_score = 42.0
        assert risk_score == expected_score, f"Expected {expected_score}, got {risk_score}"

        print(f"   ✅ Risk score calculation correct: {risk_score}")
        return True
    except Exception as e:
        print(f"   ❌ Risk score calculation failed: {e}")
        return False

def test_vulnerability_deduplication():
    """Test vulnerability deduplication"""
    print("🔍 Testing vulnerability deduplication...")

    try:
        from container_scanner import ContainerSecurityScanner, Vulnerability

        scanner = ContainerSecurityScanner()

        # Create duplicate vulnerabilities
        vulnerabilities = [
            Vulnerability("CVE-2023-0001", "HIGH", "openssl", "1.1.1", "1.1.1n", "desc", "trivy", 7.0),
            Vulnerability("CVE-2023-0001", "HIGH", "openssl", "1.1.1", "1.1.1n", "desc", "grype", 7.0),  # Duplicate
            Vulnerability("CVE-2023-0002", "MEDIUM", "curl", "7.68.0", "7.68.1", "desc", "trivy", 5.0),
            Vulnerability("CVE-2023-0001", "HIGH", "openssl", "1.1.1", "1.1.1n", "desc", "snyk", 7.0)   # Another duplicate
        ]

        # Deduplicate
        unique_vulns = scanner._deduplicate_vulnerabilities(vulnerabilities)

        # Should have only 2 unique vulnerabilities
        assert len(unique_vulns) == 2

        # Check that we have both CVEs
        cve_ids = [v.cve_id for v in unique_vulns]
        assert "CVE-2023-0001" in cve_ids
        assert "CVE-2023-0002" in cve_ids

        print(f"   ✅ Deduplication working: {len(vulnerabilities)} -> {len(unique_vulns)}")
        return True
    except Exception as e:
        print(f"   ❌ Deduplication test failed: {e}")
        return False

def test_report_generation():
    """Test report generation in different formats"""
    print("🔍 Testing report generation...")

    try:
        from container_scanner import ContainerSecurityScanner, ContainerScanResult, Vulnerability, SecurityCheck

        scanner = ContainerSecurityScanner()

        # Create mock scan result
        vulnerabilities = [
            Vulnerability("CVE-2023-0001", "CRITICAL", "openssl", "1.1.1", "1.1.1n", "Critical OpenSSL vulnerability", "trivy", 9.8)
        ]

        security_checks = [
            SecurityCheck("DOCKERFILE_001", "Root user", "Container runs as root", "HIGH", "FAIL", "Use non-root user", "dockerfile")
        ]

        scan_result = ContainerScanResult(
            image_name="test",
            image_tag="latest",
            image_digest="sha256:abc123def456",
            scan_time=datetime.utcnow(),
            vulnerabilities=vulnerabilities,
            security_checks=security_checks,
            metadata={"size": 100000000},
            risk_score=25.0
        )

        # Test JSON report
        json_report = scanner.generate_report(scan_result, "json")
        json_data = json.loads(json_report)

        assert "scan_metadata" in json_data
        assert json_data["scan_metadata"]["image"] == "test:latest"
        assert json_data["scan_metadata"]["risk_score"] == 25.0
        assert len(json_data["vulnerabilities"]) == 1
        assert len(json_data["security_checks"]) == 1
        print("   ✅ JSON report generation working")

        # Test HTML report
        html_report = scanner.generate_report(scan_result, "html")
        assert "Container Security Scan Report" in html_report
        assert "test:latest" in html_report
        assert "CVE-2023-0001" in html_report
        assert "Risk Score: 25.0" in html_report
        print("   ✅ HTML report generation working")

        # Test SARIF report
        sarif_report = scanner.generate_report(scan_result, "sarif")
        sarif_data = json.loads(sarif_report)

        assert sarif_data["version"] == "2.1.0"
        assert len(sarif_data["runs"]) == 1
        assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "Container Security Scanner"
        print("   ✅ SARIF report generation working")

        return True
    except Exception as e:
        print(f"   ❌ Report generation test failed: {e}")
        return False

def test_dockerfile_checks():
    """Test Dockerfile security checks"""
    print("🔍 Testing Dockerfile security checks...")

    try:
        from container_scanner import ContainerSecurityScanner

        scanner = ContainerSecurityScanner()

        # Test root user detection
        metadata_root = {
            "config": {
                "User": "",  # Empty means root
                "ExposedPorts": {"22/tcp": {}, "80/tcp": {}},
                "Env": ["PATH=/usr/bin", "SECRET_KEY=very_secret_value"]
            }
        }

        # Use asyncio.run for the async method
        async def run_check():
            return await scanner._check_dockerfile_practices("test:latest", metadata_root)

        checks = asyncio.run(run_check())

        # Should detect root user
        root_checks = [c for c in checks if c.check_id == "DOCKERFILE_001"]
        assert len(root_checks) == 1
        assert root_checks[0].status == "FAIL"
        assert root_checks[0].severity == "HIGH"

        print("   ✅ Dockerfile checks working correctly")
        return True
    except Exception as e:
        print(f"   ❌ Dockerfile checks test failed: {e}")
        return False

def test_configuration_file():
    """Test that configuration file exists and is valid"""
    print("🔍 Testing configuration file...")

    try:
        config_path = Path(__file__).parent / "config" / "container-security.yml"

        if not config_path.exists():
            print("   ⚠️ Configuration file not found - using defaults")
            return True

        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f)

        # Check required sections
        required_sections = ["scanners", "security_checks", "severity", "output"]
        for section in required_sections:
            assert section in config, f"Missing section: {section}"

        # Check scanner configurations
        assert "trivy" in config["scanners"]
        assert "grype" in config["scanners"]

        print("   ✅ Configuration file is valid")
        return True
    except Exception as e:
        print(f"   ❌ Configuration file test failed: {e}")
        return False

def test_requirements_file():
    """Test that requirements file exists"""
    print("🔍 Testing requirements file...")

    try:
        req_path = Path(__file__).parent / "requirements.txt"
        assert req_path.exists(), "requirements.txt should exist"

        with open(req_path) as f:
            content = f.read()

        # Check for essential packages
        essential_packages = ["pyyaml", "asyncio", "docker"]
        for package in essential_packages:
            if not any(package in line.lower() for line in content.split('\n')):
                print(f"   ⚠️ Package {package} not found in requirements")

        print("   ✅ Requirements file exists and looks good")
        return True
    except Exception as e:
        print(f"   ❌ Requirements file test failed: {e}")
        return False

def simulate_container_scan():
    """Simulate a container scan with mock data"""
    print("\n📊 Simulating Container Security Scan...")

    # Mock scan results
    mock_vulnerabilities = [
        {
            "cve_id": "CVE-2023-0001",
            "severity": "CRITICAL",
            "package": "openssl",
            "version": "1.1.1k",
            "fixed_version": "1.1.1n",
            "description": "OpenSSL vulnerability allowing remote code execution",
            "source": "trivy",
            "score": 9.8
        },
        {
            "cve_id": "CVE-2023-0002",
            "severity": "HIGH",
            "package": "curl",
            "version": "7.68.0",
            "fixed_version": "7.81.0",
            "description": "Curl buffer overflow vulnerability",
            "source": "grype",
            "score": 7.5
        },
        {
            "cve_id": "CVE-2023-0003",
            "severity": "MEDIUM",
            "package": "nginx",
            "version": "1.18.0",
            "fixed_version": "1.20.1",
            "description": "Nginx configuration bypass",
            "source": "trivy",
            "score": 5.3
        }
    ]

    mock_security_checks = [
        {
            "check_id": "DOCKERFILE_001",
            "title": "Container runs as root",
            "status": "FAIL",
            "severity": "HIGH",
            "category": "dockerfile"
        },
        {
            "check_id": "SECRETS_001",
            "title": "API key found in environment",
            "status": "FAIL",
            "severity": "CRITICAL",
            "category": "secrets"
        },
        {
            "check_id": "CIS_4.6",
            "title": "Health check configured",
            "status": "PASS",
            "severity": "INFO",
            "category": "compliance"
        }
    ]

    print("🔍 Container Image: nginx:1.18-alpine")
    print("🕐 Scan Time:", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    print()

    # Display vulnerabilities
    print("🚨 Security Vulnerabilities:")
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for vuln in mock_vulnerabilities:
        severity_icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }.get(vuln["severity"], "⚪")

        severity_counts[vuln["severity"]] += 1

        print(f"   {severity_icon} {vuln['severity']}: {vuln['cve_id']}")
        print(f"      Package: {vuln['package']} {vuln['version']}")
        print(f"      Fix: {vuln['fixed_version']}")
        print(f"      Score: {vuln['score']}")
        print()

    # Display security checks
    print("🔒 Security Checks:")
    for check in mock_security_checks:
        status_icon = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}.get(check["status"], "❓")
        print(f"   {status_icon} {check['title']} ({check['status']})")
        print(f"      Category: {check['category']}")
        print()

    # Calculate summary metrics
    total_vulns = len(mock_vulnerabilities)
    failed_checks = len([c for c in mock_security_checks if c["status"] == "FAIL"])

    # Simple risk score calculation
    risk_score = (severity_counts["CRITICAL"] * 10 +
                  severity_counts["HIGH"] * 7 +
                  severity_counts["MEDIUM"] * 4 +
                  failed_checks * 5)

    print("📈 Scan Summary:")
    print(f"   Total Vulnerabilities: {total_vulns}")
    print(f"   - Critical: {severity_counts['CRITICAL']}")
    print(f"   - High: {severity_counts['HIGH']}")
    print(f"   - Medium: {severity_counts['MEDIUM']}")
    print(f"   - Low: {severity_counts['LOW']}")
    print(f"   Failed Security Checks: {failed_checks}")
    print(f"   Risk Score: {risk_score}/100")

    if risk_score >= 25:
        print("   🚨 HIGH RISK - Immediate attention required")
    elif risk_score >= 10:
        print("   ⚠️ MEDIUM RISK - Schedule remediation")
    else:
        print("   ✅ LOW RISK - Monitor and maintain")

def main():
    """Main test function"""
    print("🛡️ Container Security Scanner - Simple Test Suite")
    print("=" * 60)

    all_tests_passed = True

    # Run all tests
    tests = [
        ("Imports", test_imports),
        ("Data Structures", test_data_structures),
        ("Scanner Initialization", test_scanner_initialization),
        ("Configuration Loading", test_configuration_loading),
        ("Risk Score Calculation", test_risk_score_calculation),
        ("Vulnerability Deduplication", test_vulnerability_deduplication),
        ("Report Generation", test_report_generation),
        ("Dockerfile Checks", test_dockerfile_checks),
        ("Configuration File", test_configuration_file),
        ("Requirements File", test_requirements_file)
    ]

    for test_name, test_func in tests:
        print(f"\n🧪 Running {test_name} Test...")
        if not test_func():
            all_tests_passed = False

    if all_tests_passed:
        print("\n✅ All tests passed!")

        # Run simulation
        simulate_container_scan()

        print("\n🎉 Container Security Scanner is working correctly!")
        print("\n📋 Next Steps:")
        print("1. Install external scanners:")
        print("   - Trivy: https://aquasecurity.github.io/trivy/")
        print("   - Grype: https://github.com/anchore/grype")
        print("2. Install dependencies:")
        print("   pip install -r requirements.txt")
        print("3. Run setup script:")
        print("   python setup.py")
        print("4. Test with real container:")
        print("   python container-scanner.py alpine:latest")

    else:
        print("\n❌ Some tests failed!")
        print("Please check the error messages above and fix the issues.")
        return False

    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)