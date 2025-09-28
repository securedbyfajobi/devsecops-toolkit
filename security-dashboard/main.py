#!/usr/bin/env python3
"""
Security Monitoring Dashboard
Enterprise-grade security visualization and monitoring platform
Aggregates security data from multiple sources and provides real-time insights
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from pydantic import BaseModel, Field
import aioredis
import asyncpg
import httpx
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security-dashboard.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration Models
@dataclass
class SecurityConfig:
    """Security dashboard configuration"""
    refresh_interval: int = 60  # seconds
    alert_threshold_critical: int = 0
    alert_threshold_high: int = 5
    alert_threshold_medium: int = 20
    data_retention_days: int = 90
    enable_real_time: bool = True
    enable_notifications: bool = True

class CloudProvider(BaseModel):
    """Cloud provider configuration"""
    name: str
    enabled: bool
    region: str
    credentials: Dict[str, str] = Field(default_factory=dict)
    endpoints: Dict[str, str] = Field(default_factory=dict)

class SecurityMetric(BaseModel):
    """Security metric data model"""
    timestamp: datetime
    source: str
    metric_type: str
    severity: str
    value: float
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SecurityFinding(BaseModel):
    """Security finding data model"""
    id: str
    title: str
    description: str
    severity: str
    source: str
    resource_type: str
    resource_id: str
    region: str
    account_id: str
    compliance_frameworks: List[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class ComplianceStatus(BaseModel):
    """Compliance status model"""
    framework: str
    total_controls: int
    passing_controls: int
    failing_controls: int
    compliance_score: float
    last_assessed: datetime

# FastAPI Application
app = FastAPI(
    title="Security Monitoring Dashboard",
    description="Enterprise Security Monitoring and Compliance Dashboard",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Global variables
config: SecurityConfig = SecurityConfig()
cloud_providers: Dict[str, CloudProvider] = {}
redis_client: Optional[aioredis.Redis] = None
db_pool: Optional[asyncpg.Pool] = None

class SecurityDataCollector:
    """Collects security data from various sources"""

    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=30.0)

    async def collect_aws_security_data(self, provider: CloudProvider) -> List[SecurityFinding]:
        """Collect security findings from AWS Security Hub"""
        findings = []

        try:
            # AWS Security Hub API integration
            if 'security_hub_endpoint' in provider.endpoints:
                logger.info(f"Collecting AWS Security Hub data for {provider.region}")

                # Simulate AWS Security Hub API call
                # In production, use boto3 with proper credentials
                mock_findings = [
                    {
                        "id": "aws-securityhub-001",
                        "title": "EC2 instance with unrestricted SSH access",
                        "description": "Security group allows SSH (port 22) from 0.0.0.0/0",
                        "severity": "HIGH",
                        "source": "aws-security-hub",
                        "resource_type": "AWS::EC2::SecurityGroup",
                        "resource_id": "sg-0123456789abcdef0",
                        "region": provider.region,
                        "account_id": "123456789012",
                        "compliance_frameworks": ["CIS", "AWS_FOUNDATIONAL"],
                        "remediation": "Remove 0.0.0.0/0 source from SSH rule",
                        "created_at": datetime.utcnow(),
                        "updated_at": datetime.utcnow()
                    }
                ]

                for finding_data in mock_findings:
                    finding = SecurityFinding(**finding_data)
                    findings.append(finding)

        except Exception as e:
            logger.error(f"Error collecting AWS data: {e}")

        return findings

    async def collect_azure_security_data(self, provider: CloudProvider) -> List[SecurityFinding]:
        """Collect security findings from Azure Security Center"""
        findings = []

        try:
            if 'security_center_endpoint' in provider.endpoints:
                logger.info(f"Collecting Azure Security Center data for {provider.region}")

                # Simulate Azure Security Center API call
                mock_findings = [
                    {
                        "id": "azure-asc-001",
                        "title": "Storage account allows unsecure HTTP traffic",
                        "description": "Storage account configured to allow HTTP traffic",
                        "severity": "MEDIUM",
                        "source": "azure-security-center",
                        "resource_type": "Microsoft.Storage/storageAccounts",
                        "resource_id": "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/storage123",
                        "region": provider.region,
                        "account_id": "subscription-123",
                        "compliance_frameworks": ["CIS", "AZURE_SECURITY_BENCHMARK"],
                        "remediation": "Enable HTTPS only for storage account",
                        "created_at": datetime.utcnow(),
                        "updated_at": datetime.utcnow()
                    }
                ]

                for finding_data in mock_findings:
                    finding = SecurityFinding(**finding_data)
                    findings.append(finding)

        except Exception as e:
            logger.error(f"Error collecting Azure data: {e}")

        return findings

    async def collect_kubernetes_security_data(self) -> List[SecurityFinding]:
        """Collect security findings from Kubernetes (Falco, etc.)"""
        findings = []

        try:
            logger.info("Collecting Kubernetes security data")

            # Simulate Falco security findings
            mock_findings = [
                {
                    "id": "k8s-falco-001",
                    "title": "Suspicious process spawned in container",
                    "description": "Unexpected process execution detected in production container",
                    "severity": "CRITICAL",
                    "source": "falco",
                    "resource_type": "Pod",
                    "resource_id": "pod/suspicious-app-7d9f8b6c5d-x9z2m",
                    "region": "us-east-1",
                    "account_id": "k8s-cluster-prod",
                    "compliance_frameworks": ["CIS_KUBERNETES", "NIST"],
                    "remediation": "Investigate container and terminate if malicious",
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
            ]

            for finding_data in mock_findings:
                finding = SecurityFinding(**finding_data)
                findings.append(finding)

        except Exception as e:
            logger.error(f"Error collecting Kubernetes data: {e}")

        return findings

    async def collect_all_findings(self) -> List[SecurityFinding]:
        """Collect security findings from all configured sources"""
        all_findings = []

        # Collect from cloud providers
        for provider_name, provider in cloud_providers.items():
            if not provider.enabled:
                continue

            if provider.name == "aws":
                findings = await self.collect_aws_security_data(provider)
                all_findings.extend(findings)
            elif provider.name == "azure":
                findings = await self.collect_azure_security_data(provider)
                all_findings.extend(findings)

        # Collect from Kubernetes
        k8s_findings = await self.collect_kubernetes_security_data()
        all_findings.extend(k8s_findings)

        return all_findings

class SecurityAnalyzer:
    """Analyzes security data and generates insights"""

    def __init__(self):
        self.collector = SecurityDataCollector()

    def calculate_risk_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate overall risk score based on findings"""
        score = 0.0

        for finding in findings:
            if finding.severity == "CRITICAL":
                score += 10.0
            elif finding.severity == "HIGH":
                score += 5.0
            elif finding.severity == "MEDIUM":
                score += 2.0
            elif finding.severity == "LOW":
                score += 1.0

        # Normalize to 0-100 scale
        max_score = len(findings) * 10.0
        if max_score > 0:
            return min((score / max_score) * 100, 100.0)

        return 0.0

    def analyze_trends(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Analyze security trends"""
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        # Count findings by time period
        recent_findings = [f for f in findings if f.created_at >= last_24h]
        weekly_findings = [f for f in findings if f.created_at >= last_7d]

        # Severity distribution
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        # Source distribution
        source_counts = {}
        for finding in findings:
            source_counts[finding.source] = source_counts.get(finding.source, 0) + 1

        return {
            "total_findings": len(findings),
            "recent_findings_24h": len(recent_findings),
            "weekly_findings": len(weekly_findings),
            "severity_distribution": severity_counts,
            "source_distribution": source_counts,
            "risk_score": self.calculate_risk_score(findings),
            "trend_direction": "increasing" if len(recent_findings) > len(weekly_findings) / 7 else "decreasing"
        }

    def generate_compliance_report(self, findings: List[SecurityFinding]) -> List[ComplianceStatus]:
        """Generate compliance status report"""
        frameworks = ["CIS", "NIST", "SOC2", "PCI_DSS", "AWS_FOUNDATIONAL", "AZURE_SECURITY_BENCHMARK"]
        compliance_report = []

        for framework in frameworks:
            framework_findings = [
                f for f in findings
                if framework in f.compliance_frameworks
            ]

            if framework_findings:
                failing_controls = len([f for f in framework_findings if f.severity in ["CRITICAL", "HIGH"]])
                total_controls = len(framework_findings)
                passing_controls = total_controls - failing_controls

                compliance_score = (passing_controls / total_controls * 100) if total_controls > 0 else 100.0

                status = ComplianceStatus(
                    framework=framework,
                    total_controls=total_controls,
                    passing_controls=passing_controls,
                    failing_controls=failing_controls,
                    compliance_score=compliance_score,
                    last_assessed=datetime.utcnow()
                )
                compliance_report.append(status)

        return compliance_report

# Background task for data collection
async def collect_security_data_task():
    """Background task to collect security data periodically"""
    analyzer = SecurityAnalyzer()

    while True:
        try:
            logger.info("Starting security data collection...")

            # Collect findings
            findings = await analyzer.collector.collect_all_findings()

            # Analyze data
            trends = analyzer.analyze_trends(findings)
            compliance = analyzer.generate_compliance_report(findings)

            # Store in Redis for real-time access
            if redis_client:
                await redis_client.setex(
                    "security_findings",
                    config.refresh_interval * 2,
                    json.dumps([f.dict() for f in findings], default=str)
                )
                await redis_client.setex(
                    "security_trends",
                    config.refresh_interval * 2,
                    json.dumps(trends, default=str)
                )
                await redis_client.setex(
                    "compliance_status",
                    config.refresh_interval * 2,
                    json.dumps([c.dict() for c in compliance], default=str)
                )

            # Store in database for historical analysis
            if db_pool:
                await store_findings_in_db(findings)
                await store_metrics_in_db(trends)

            logger.info(f"Collected {len(findings)} security findings")

        except Exception as e:
            logger.error(f"Error in data collection task: {e}")

        # Wait before next collection
        await asyncio.sleep(config.refresh_interval)

async def store_findings_in_db(findings: List[SecurityFinding]):
    """Store security findings in database"""
    if not db_pool:
        return

    async with db_pool.acquire() as conn:
        for finding in findings:
            await conn.execute("""
                INSERT INTO security_findings
                (id, title, description, severity, source, resource_type, resource_id,
                 region, account_id, compliance_frameworks, remediation, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (id) DO UPDATE SET
                    updated_at = $13,
                    severity = $4,
                    description = $3
            """,
            finding.id, finding.title, finding.description, finding.severity,
            finding.source, finding.resource_type, finding.resource_id,
            finding.region, finding.account_id, finding.compliance_frameworks,
            finding.remediation, finding.created_at, finding.updated_at)

async def store_metrics_in_db(metrics: Dict[str, Any]):
    """Store security metrics in database"""
    if not db_pool:
        return

    async with db_pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO security_metrics
            (timestamp, total_findings, critical_count, high_count, medium_count,
             low_count, risk_score, trend_direction)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        """,
        datetime.utcnow(),
        metrics["total_findings"],
        metrics["severity_distribution"]["CRITICAL"],
        metrics["severity_distribution"]["HIGH"],
        metrics["severity_distribution"]["MEDIUM"],
        metrics["severity_distribution"]["LOW"],
        metrics["risk_score"],
        metrics["trend_direction"])

# API Endpoints
@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "version": "2.0.0",
        "services": {
            "redis": redis_client is not None,
            "database": db_pool is not None
        }
    }

@app.get("/api/security/findings")
async def get_security_findings(
    severity: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100
):
    """Get security findings with optional filtering"""
    try:
        if redis_client:
            findings_data = await redis_client.get("security_findings")
            if findings_data:
                findings = json.loads(findings_data)

                # Apply filters
                if severity:
                    findings = [f for f in findings if f["severity"] == severity.upper()]
                if source:
                    findings = [f for f in findings if f["source"] == source]

                return findings[:limit]

        return []
    except Exception as e:
        logger.error(f"Error getting findings: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/security/trends")
async def get_security_trends():
    """Get security trends and analytics"""
    try:
        if redis_client:
            trends_data = await redis_client.get("security_trends")
            if trends_data:
                return json.loads(trends_data)

        return {
            "total_findings": 0,
            "recent_findings_24h": 0,
            "risk_score": 0.0,
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }
    except Exception as e:
        logger.error(f"Error getting trends: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/compliance/status")
async def get_compliance_status():
    """Get compliance status across frameworks"""
    try:
        if redis_client:
            compliance_data = await redis_client.get("compliance_status")
            if compliance_data:
                return json.loads(compliance_data)

        return []
    except Exception as e:
        logger.error(f"Error getting compliance status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/security/metrics/historical")
async def get_historical_metrics(days: int = 30):
    """Get historical security metrics"""
    try:
        if not db_pool:
            return []

        async with db_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT timestamp, total_findings, critical_count, high_count,
                       medium_count, low_count, risk_score, trend_direction
                FROM security_metrics
                WHERE timestamp >= $1
                ORDER BY timestamp DESC
            """, datetime.utcnow() - timedelta(days=days))

            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting historical metrics: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/security/alert")
async def create_security_alert(
    title: str,
    description: str,
    severity: str,
    source: str
):
    """Create a custom security alert"""
    try:
        alert = SecurityFinding(
            id=f"custom-{datetime.utcnow().timestamp()}",
            title=title,
            description=description,
            severity=severity.upper(),
            source=source,
            resource_type="Custom",
            resource_id="manual-alert",
            region="global",
            account_id="dashboard",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        # Store alert
        if redis_client:
            await redis_client.lpush("custom_alerts", alert.json())
            await redis_client.expire("custom_alerts", 86400)  # Expire in 24 hours

        logger.info(f"Custom alert created: {title}")
        return {"status": "success", "alert_id": alert.id}

    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global redis_client, db_pool, cloud_providers

    logger.info("Starting Security Monitoring Dashboard...")

    # Load configuration
    config_file = os.getenv("SECURITY_CONFIG", "config/security-dashboard.yml")
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)

        # Update cloud providers configuration
        if 'cloud_providers' in config_data:
            for provider_config in config_data['cloud_providers']:
                provider = CloudProvider(**provider_config)
                cloud_providers[provider.name] = provider

    # Initialize Redis
    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        redis_client = await aioredis.from_url(redis_url)
        logger.info("Connected to Redis")
    except Exception as e:
        logger.warning(f"Failed to connect to Redis: {e}")

    # Initialize Database
    try:
        db_url = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/security_dashboard")
        db_pool = await asyncpg.create_pool(db_url)
        logger.info("Connected to database")

        # Create tables if they don't exist
        async with db_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS security_findings (
                    id VARCHAR PRIMARY KEY,
                    title VARCHAR NOT NULL,
                    description TEXT,
                    severity VARCHAR NOT NULL,
                    source VARCHAR NOT NULL,
                    resource_type VARCHAR,
                    resource_id VARCHAR,
                    region VARCHAR,
                    account_id VARCHAR,
                    compliance_frameworks JSONB,
                    remediation TEXT,
                    created_at TIMESTAMP WITH TIME ZONE,
                    updated_at TIMESTAMP WITH TIME ZONE
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS security_metrics (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP WITH TIME ZONE,
                    total_findings INTEGER,
                    critical_count INTEGER,
                    high_count INTEGER,
                    medium_count INTEGER,
                    low_count INTEGER,
                    risk_score FLOAT,
                    trend_direction VARCHAR
                )
            """)

    except Exception as e:
        logger.warning(f"Failed to connect to database: {e}")

    # Start background data collection
    asyncio.create_task(collect_security_data_task())

    logger.info("Security Monitoring Dashboard started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Security Monitoring Dashboard...")

    if redis_client:
        await redis_client.close()

    if db_pool:
        await db_pool.close()

if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )