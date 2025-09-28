#!/usr/bin/env python3
"""
Simple test script for Security Monitoring Dashboard
Tests basic functionality without external dependencies
"""

import sys
import json
import asyncio
from datetime import datetime
from pathlib import Path

# Test configuration and setup
def test_files_exist():
    """Test that all required files exist"""
    print("🔍 Checking required files...")

    required_files = [
        "main.py",
        "requirements.txt",
        "config/security-dashboard.yml",
        "templates/dashboard.html",
        "setup.py"
    ]

    base_path = Path(__file__).parent

    for file_path in required_files:
        full_path = base_path / file_path
        if full_path.exists():
            print(f"   ✅ {file_path}")
        else:
            print(f"   ❌ {file_path} - MISSING")
            return False

    return True

def test_configuration():
    """Test configuration file validity"""
    print("🔧 Testing configuration...")

    try:
        import yaml

        config_file = Path(__file__).parent / "config" / "security-dashboard.yml"
        with open(config_file) as f:
            config = yaml.safe_load(f)

        required_sections = ["app", "security", "cloud_providers", "compliance_frameworks"]
        for section in required_sections:
            if section not in config:
                print(f"   ❌ Missing section: {section}")
                return False
            else:
                print(f"   ✅ Section exists: {section}")

        return True

    except Exception as e:
        print(f"   ❌ Configuration error: {e}")
        return False

def test_basic_imports():
    """Test that the main application can be imported"""
    print("📦 Testing imports...")

    try:
        # Test basic Python imports
        import json
        import asyncio
        from datetime import datetime
        print("   ✅ Standard library imports")

        # Test that main module can be parsed
        main_file = Path(__file__).parent / "main.py"
        with open(main_file) as f:
            content = f.read()

        # Basic syntax check
        compile(content, "main.py", "exec")
        print("   ✅ Main application syntax is valid")

        return True

    except Exception as e:
        print(f"   ❌ Import error: {e}")
        return False

def test_mock_security_data():
    """Test security data structures and processing"""
    print("🛡️  Testing security data processing...")

    try:
        # Mock security finding
        finding = {
            "id": "test-001",
            "title": "Test Security Finding",
            "description": "This is a test security finding for validation",
            "severity": "HIGH",
            "source": "test-system",
            "resource_type": "TestResource",
            "resource_id": "test-resource-123",
            "region": "us-east-1",
            "account_id": "123456789012",
            "compliance_frameworks": ["CIS", "NIST"],
            "remediation": "This is test remediation guidance",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }

        # Test JSON serialization
        json_data = json.dumps(finding, default=str)
        parsed_data = json.loads(json_data)

        assert parsed_data["id"] == "test-001"
        assert parsed_data["severity"] == "HIGH"
        print("   ✅ Security finding data structure is valid")

        # Mock compliance data
        compliance = {
            "framework": "CIS",
            "total_controls": 100,
            "passing_controls": 85,
            "failing_controls": 15,
            "compliance_score": 85.0,
            "last_assessed": datetime.utcnow().isoformat()
        }

        compliance_json = json.dumps(compliance, default=str)
        parsed_compliance = json.loads(compliance_json)

        assert parsed_compliance["compliance_score"] == 85.0
        print("   ✅ Compliance data structure is valid")

        # Mock metrics data
        metrics = {
            "total_findings": 25,
            "recent_findings_24h": 5,
            "weekly_findings": 18,
            "severity_distribution": {
                "CRITICAL": 2,
                "HIGH": 8,
                "MEDIUM": 10,
                "LOW": 5
            },
            "source_distribution": {
                "aws-security-hub": 15,
                "azure-security-center": 7,
                "falco": 3
            },
            "risk_score": 45.5,
            "trend_direction": "decreasing"
        }

        # Test risk score calculation
        total_severity_score = (metrics["severity_distribution"]["CRITICAL"] * 10 +
                              metrics["severity_distribution"]["HIGH"] * 5 +
                              metrics["severity_distribution"]["MEDIUM"] * 2 +
                              metrics["severity_distribution"]["LOW"] * 1)

        max_possible = metrics["total_findings"] * 10
        calculated_risk = (total_severity_score / max_possible * 100) if max_possible > 0 else 0

        print(f"   ✅ Risk score calculation: {calculated_risk:.1f}%")

        return True

    except Exception as e:
        print(f"   ❌ Data processing error: {e}")
        return False

def test_template_validity():
    """Test HTML template structure"""
    print("🎨 Testing HTML template...")

    try:
        template_file = Path(__file__).parent / "templates" / "dashboard.html"
        with open(template_file) as f:
            content = f.read()

        # Check for required elements
        required_elements = [
            "Security Monitoring Dashboard",
            "totalFindings",
            "riskScore",
            "severityChart",
            "complianceStatus",
            "findingsTableBody"
        ]

        for element in required_elements:
            if element in content:
                print(f"   ✅ Element found: {element}")
            else:
                print(f"   ❌ Missing element: {element}")
                return False

        # Check for Bootstrap and Chart.js
        if "bootstrap" in content and "chart.js" in content:
            print("   ✅ Required libraries included")
        else:
            print("   ❌ Missing required libraries")
            return False

        return True

    except Exception as e:
        print(f"   ❌ Template error: {e}")
        return False

def simulate_dashboard_data():
    """Simulate live dashboard data"""
    print("\n📊 Simulating Dashboard Data...")

    # Generate sample findings
    sample_findings = [
        {
            "id": "aws-001",
            "title": "S3 bucket with public read access",
            "severity": "HIGH",
            "source": "aws-security-hub",
            "resource_type": "AWS::S3::Bucket",
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "id": "azure-001",
            "title": "Virtual machine without disk encryption",
            "severity": "MEDIUM",
            "source": "azure-security-center",
            "resource_type": "Microsoft.Compute/virtualMachines",
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "id": "k8s-001",
            "title": "Privileged container detected",
            "severity": "CRITICAL",
            "source": "falco",
            "resource_type": "Pod",
            "created_at": datetime.utcnow().isoformat()
        }
    ]

    print("🔍 Sample Security Findings:")
    for finding in sample_findings:
        severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = severity_icon.get(finding["severity"], "⚪")
        print(f"   {icon} {finding['severity']}: {finding['title']}")
        print(f"      Source: {finding['source']}")
        print(f"      Type: {finding['resource_type']}")
        print("")

    # Calculate metrics
    severity_counts = {}
    source_counts = {}

    for finding in sample_findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
        source_counts[finding["source"]] = source_counts.get(finding["source"], 0) + 1

    print("📈 Dashboard Metrics:")
    print(f"   Total Findings: {len(sample_findings)}")
    print(f"   Critical: {severity_counts.get('CRITICAL', 0)}")
    print(f"   High: {severity_counts.get('HIGH', 0)}")
    print(f"   Medium: {severity_counts.get('MEDIUM', 0)}")
    print(f"   Low: {severity_counts.get('LOW', 0)}")

    # Calculate risk score
    total_score = (severity_counts.get('CRITICAL', 0) * 10 +
                   severity_counts.get('HIGH', 0) * 5 +
                   severity_counts.get('MEDIUM', 0) * 2 +
                   severity_counts.get('LOW', 0) * 1)

    max_score = len(sample_findings) * 10
    risk_score = (total_score / max_score * 100) if max_score > 0 else 0
    print(f"   Risk Score: {risk_score:.1f}%")

    print("\n📊 Source Distribution:")
    for source, count in source_counts.items():
        print(f"   {source}: {count}")

    # Mock compliance status
    compliance_frameworks = [
        {"name": "CIS", "score": 78},
        {"name": "NIST", "score": 82},
        {"name": "SOC2", "score": 89},
        {"name": "PCI DSS", "score": 75}
    ]

    print("\n🏆 Compliance Status:")
    for framework in compliance_frameworks:
        status_icon = "✅" if framework["score"] >= 80 else "⚠️" if framework["score"] >= 60 else "❌"
        print(f"   {status_icon} {framework['name']}: {framework['score']}%")

    return {
        "findings": sample_findings,
        "metrics": {
            "total_findings": len(sample_findings),
            "severity_distribution": severity_counts,
            "source_distribution": source_counts,
            "risk_score": risk_score
        },
        "compliance": compliance_frameworks
    }

def main():
    """Main test function"""
    print("🛡️  Security Monitoring Dashboard - Simple Test Suite")
    print("=" * 60)

    all_tests_passed = True

    # Run tests
    tests = [
        ("File Structure", test_files_exist),
        ("Configuration", test_configuration),
        ("Basic Imports", test_basic_imports),
        ("Data Processing", test_mock_security_data),
        ("HTML Template", test_template_validity)
    ]

    for test_name, test_func in tests:
        print(f"\n🧪 Running {test_name} Test...")
        if not test_func():
            all_tests_passed = False

    if all_tests_passed:
        print("\n✅ All tests passed!")

        # Simulate dashboard data
        dashboard_data = simulate_dashboard_data()

        print("\n🎉 Security Dashboard is ready!")
        print("\n📋 Next Steps:")
        print("1. Install dependencies:")
        print("   pip install fastapi uvicorn jinja2 pyyaml")
        print("2. Run the dashboard:")
        print("   python main.py")
        print("3. Open browser:")
        print("   http://localhost:8080")
        print("\n💡 For full setup:")
        print("   python setup.py")

    else:
        print("\n❌ Some tests failed!")
        print("Please check the file structure and configuration")
        return False

    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)