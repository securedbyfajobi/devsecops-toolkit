#!/usr/bin/env python3
"""
Test script for Security Monitoring Dashboard
Validates functionality without external dependencies
"""

import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest
import httpx
from fastapi.testclient import TestClient

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import the main application
from main import app, SecurityDataCollector, SecurityAnalyzer, SecurityFinding

# Test client
client = TestClient(app)

class TestSecurityDashboard:
    """Test suite for the security dashboard"""

    def test_health_endpoint(self):
        """Test the health check endpoint"""
        response = client.get("/api/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data

    def test_dashboard_home_page(self):
        """Test the main dashboard page loads"""
        response = client.get("/")
        assert response.status_code == 200
        assert "Security Monitoring Dashboard" in response.text

    def test_security_findings_endpoint(self):
        """Test the security findings API endpoint"""
        response = client.get("/api/security/findings")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

    def test_security_trends_endpoint(self):
        """Test the security trends API endpoint"""
        response = client.get("/api/security/trends")
        assert response.status_code == 200

        data = response.json()
        assert "total_findings" in data
        assert "risk_score" in data
        assert "severity_distribution" in data

    def test_compliance_status_endpoint(self):
        """Test the compliance status API endpoint"""
        response = client.get("/api/compliance/status")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

    def test_findings_filtering(self):
        """Test filtering of security findings"""
        # Test severity filter
        response = client.get("/api/security/findings?severity=HIGH")
        assert response.status_code == 200

        # Test source filter
        response = client.get("/api/security/findings?source=aws-security-hub")
        assert response.status_code == 200

        # Test combined filters
        response = client.get("/api/security/findings?severity=CRITICAL&source=falco")
        assert response.status_code == 200

    def test_historical_metrics_endpoint(self):
        """Test the historical metrics endpoint"""
        response = client.get("/api/security/metrics/historical?days=7")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

    def test_custom_alert_creation(self):
        """Test creating custom security alerts"""
        alert_data = {
            "title": "Test Security Alert",
            "description": "This is a test alert for validation",
            "severity": "HIGH",
            "source": "test-dashboard"
        }

        response = client.post("/api/security/alert", params=alert_data)
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "success"
        assert "alert_id" in data

    @pytest.mark.asyncio
    async def test_security_data_collector(self):
        """Test the security data collector"""
        collector = SecurityDataCollector()

        # Test with mock provider data
        from main import CloudProvider

        aws_provider = CloudProvider(
            name="aws",
            enabled=True,
            region="us-east-1",
            endpoints={"security_hub_endpoint": "https://test-endpoint.com"}
        )

        findings = await collector.collect_aws_security_data(aws_provider)
        assert isinstance(findings, list)

        # Test Kubernetes data collection
        k8s_findings = await collector.collect_kubernetes_security_data()
        assert isinstance(k8s_findings, list)

    def test_security_analyzer(self):
        """Test the security analyzer functionality"""
        analyzer = SecurityAnalyzer()

        # Create test findings
        test_findings = [
            SecurityFinding(
                id="test-1",
                title="Test Critical Finding",
                description="Test description",
                severity="CRITICAL",
                source="test",
                resource_type="Test",
                resource_id="test-resource-1",
                region="us-east-1",
                account_id="123456789012",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ),
            SecurityFinding(
                id="test-2",
                title="Test High Finding",
                description="Test description",
                severity="HIGH",
                source="test",
                resource_type="Test",
                resource_id="test-resource-2",
                region="us-east-1",
                account_id="123456789012",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        ]

        # Test risk score calculation
        risk_score = analyzer.calculate_risk_score(test_findings)
        assert 0 <= risk_score <= 100

        # Test trend analysis
        trends = analyzer.analyze_trends(test_findings)
        assert "total_findings" in trends
        assert "severity_distribution" in trends
        assert trends["total_findings"] == 2

        # Test compliance report generation
        compliance_report = analyzer.generate_compliance_report(test_findings)
        assert isinstance(compliance_report, list)

def test_configuration_loading():
    """Test configuration file loading"""
    config_path = Path(__file__).parent / "config" / "security-dashboard.yml"
    assert config_path.exists(), "Configuration file should exist"

def test_template_files():
    """Test that template files exist"""
    template_path = Path(__file__).parent / "templates" / "dashboard.html"
    assert template_path.exists(), "Dashboard template should exist"

def test_requirements_file():
    """Test that requirements file exists and is valid"""
    req_path = Path(__file__).parent / "requirements.txt"
    assert req_path.exists(), "Requirements file should exist"

    with open(req_path) as f:
        content = f.read()
        assert "fastapi" in content
        assert "uvicorn" in content

def run_integration_tests():
    """Run integration tests to verify the dashboard works end-to-end"""
    print("🧪 Running Security Dashboard Integration Tests...")

    # Test 1: Basic API functionality
    print("✅ Testing API endpoints...")
    try:
        response = client.get("/api/health")
        assert response.status_code == 200
        print("   ✓ Health endpoint working")

        response = client.get("/api/security/trends")
        assert response.status_code == 200
        print("   ✓ Trends endpoint working")

        response = client.get("/api/security/findings")
        assert response.status_code == 200
        print("   ✓ Findings endpoint working")

    except Exception as e:
        print(f"   ❌ API test failed: {e}")
        return False

    # Test 2: Dashboard page rendering
    print("✅ Testing dashboard page...")
    try:
        response = client.get("/")
        assert response.status_code == 200
        assert "Security Monitoring Dashboard" in response.text
        print("   ✓ Dashboard page renders correctly")
    except Exception as e:
        print(f"   ❌ Dashboard page test failed: {e}")
        return False

    # Test 3: Data processing
    print("✅ Testing data processing...")
    try:
        analyzer = SecurityAnalyzer()

        # Test with sample data
        sample_findings = [
            SecurityFinding(
                id="integration-test-1",
                title="Integration Test Finding",
                description="Test finding for integration testing",
                severity="HIGH",
                source="integration-test",
                resource_type="TestResource",
                resource_id="test-123",
                region="us-east-1",
                account_id="test-account",
                compliance_frameworks=["CIS", "NIST"],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        ]

        trends = analyzer.analyze_trends(sample_findings)
        assert trends["total_findings"] == 1
        assert trends["risk_score"] >= 0
        print("   ✓ Data analysis working correctly")

    except Exception as e:
        print(f"   ❌ Data processing test failed: {e}")
        return False

    # Test 4: Configuration validation
    print("✅ Testing configuration...")
    try:
        config_path = Path(__file__).parent / "config" / "security-dashboard.yml"
        assert config_path.exists()

        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f)
            assert "app" in config
            assert "security" in config
            assert "cloud_providers" in config
        print("   ✓ Configuration file is valid")

    except Exception as e:
        print(f"   ❌ Configuration test failed: {e}")
        return False

    print("\n🎉 All integration tests passed! Dashboard is working correctly.")
    return True

def simulate_live_data():
    """Simulate live security data for demonstration"""
    print("\n📊 Simulating live security data...")

    # Create sample findings that would come from real security tools
    sample_findings = [
        {
            "id": "aws-sh-001",
            "title": "EC2 instance with unrestricted SSH access",
            "description": "Security group sg-0123456789abcdef0 allows SSH (port 22) access from 0.0.0.0/0",
            "severity": "HIGH",
            "source": "aws-security-hub",
            "resource_type": "AWS::EC2::SecurityGroup",
            "resource_id": "sg-0123456789abcdef0",
            "region": "us-east-1",
            "account_id": "123456789012",
            "compliance_frameworks": ["CIS", "AWS_FOUNDATIONAL"],
            "remediation": "Remove 0.0.0.0/0 source from SSH rule or restrict to specific IP ranges",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        },
        {
            "id": "azure-asc-001",
            "title": "Storage account allows HTTP traffic",
            "description": "Storage account 'companystorage123' is configured to allow HTTP traffic",
            "severity": "MEDIUM",
            "source": "azure-security-center",
            "resource_type": "Microsoft.Storage/storageAccounts",
            "resource_id": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/companystorage123",
            "region": "East US",
            "account_id": "subscription-123",
            "compliance_frameworks": ["CIS", "AZURE_SECURITY_BENCHMARK"],
            "remediation": "Configure storage account to require HTTPS only",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        },
        {
            "id": "k8s-falco-001",
            "title": "Unexpected shell access in container",
            "description": "Shell process detected in production container 'web-app-7d9f8b6c5d-x9z2m'",
            "severity": "CRITICAL",
            "source": "falco",
            "resource_type": "Pod",
            "resource_id": "web-app-7d9f8b6c5d-x9z2m",
            "region": "us-east-1",
            "account_id": "k8s-cluster-prod",
            "compliance_frameworks": ["CIS_KUBERNETES", "NIST"],
            "remediation": "Investigate container activity and terminate if unauthorized",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
    ]

    print(f"Generated {len(sample_findings)} sample security findings:")
    for finding in sample_findings:
        severity_icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }.get(finding["severity"], "⚪")

        print(f"  {severity_icon} {finding['severity']}: {finding['title']}")
        print(f"     Source: {finding['source']}")
        print(f"     Resource: {finding['resource_id']}")
        print("")

    # Calculate summary metrics
    severity_counts = {}
    source_counts = {}

    for finding in sample_findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
        source_counts[finding["source"]] = source_counts.get(finding["source"], 0) + 1

    print("📈 Security Metrics Summary:")
    print(f"   Total Findings: {len(sample_findings)}")
    print(f"   Critical: {severity_counts.get('CRITICAL', 0)}")
    print(f"   High: {severity_counts.get('HIGH', 0)}")
    print(f"   Medium: {severity_counts.get('MEDIUM', 0)}")
    print(f"   Low: {severity_counts.get('LOW', 0)}")
    print("")
    print("📊 Sources:")
    for source, count in source_counts.items():
        print(f"   {source}: {count}")

    return sample_findings

if __name__ == "__main__":
    print("🛡️  Security Monitoring Dashboard - Test Suite")
    print("=" * 50)

    # Run integration tests
    success = run_integration_tests()

    if success:
        # Simulate live data
        simulate_live_data()

        print("\n🚀 Dashboard is ready!")
        print("   To start the dashboard:")
        print("   1. Install dependencies: pip install -r requirements.txt")
        print("   2. Run the server: python main.py")
        print("   3. Open browser: http://localhost:8080")

    else:
        print("\n❌ Some tests failed. Please check the configuration.")
        sys.exit(1)