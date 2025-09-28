#!/usr/bin/env python3
"""
Setup script for Security Monitoring Dashboard
Handles installation, configuration, and deployment
"""

import os
import sys
import subprocess
import shutil
import yaml
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3.8, 0):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} detected")

def install_dependencies():
    """Install required Python dependencies"""
    print("📦 Installing dependencies...")

    requirements_file = Path(__file__).parent / "requirements.txt"
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False

    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
        ], check=True, capture_output=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    directories = [
        "logs",
        "data",
        "static",
        "templates",
        "config",
        "outputs"
    ]

    for directory in directories:
        dir_path = Path(__file__).parent / directory
        dir_path.mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def setup_environment():
    """Setup environment variables and configuration"""
    env_file = Path(__file__).parent / ".env"

    if not env_file.exists():
        print("📝 Creating environment configuration...")

        env_content = """# Security Dashboard Environment Configuration
# Database Configuration
DATABASE_URL=postgresql://postgres:password@localhost:5432/security_dashboard

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# AWS Configuration (optional)
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_SESSION_TOKEN=your_aws_session_token

# Azure Configuration (optional)
AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_client_secret
AZURE_TENANT_ID=your_azure_tenant_id
AZURE_SUBSCRIPTION_ID=your_azure_subscription_id

# GCP Configuration (optional)
GCP_SERVICE_ACCOUNT_KEY=path/to/service-account-key.json
GCP_PROJECT_ID=your_gcp_project_id

# SMTP Configuration for alerts
SMTP_USERNAME=your_smtp_username
SMTP_PASSWORD=your_smtp_password

# Webhook URLs for notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/slack/webhook
TEAMS_WEBHOOK_URL=https://your.webhook.office.com/your/teams/webhook

# SIEM Integration (optional)
SIEM_USERNAME=your_siem_username
SIEM_PASSWORD=your_siem_password

# API Security
API_SECRET_KEY=your_super_secret_key_here_change_this_in_production
"""

        with open(env_file, 'w') as f:
            f.write(env_content)

        print(f"✅ Environment file created: {env_file}")
        print("⚠️  Please update the .env file with your actual credentials")

def validate_configuration():
    """Validate the configuration file"""
    config_file = Path(__file__).parent / "config" / "security-dashboard.yml"

    if not config_file.exists():
        print("❌ Configuration file not found")
        return False

    try:
        with open(config_file) as f:
            config = yaml.safe_load(f)

        # Validate required sections
        required_sections = ["app", "security", "cloud_providers", "compliance_frameworks"]
        for section in required_sections:
            if section not in config:
                print(f"❌ Missing required configuration section: {section}")
                return False

        print("✅ Configuration file is valid")
        return True

    except yaml.YAMLError as e:
        print(f"❌ Invalid YAML in configuration file: {e}")
        return False

def setup_database():
    """Setup database (optional - for development)"""
    print("🗄️  Setting up database...")

    # Check if PostgreSQL is available
    try:
        result = subprocess.run(
            ["psql", "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("✅ PostgreSQL detected")

            # Try to create database
            try:
                subprocess.run([
                    "createdb", "security_dashboard"
                ], capture_output=True, check=True)
                print("✅ Database 'security_dashboard' created")
            except subprocess.CalledProcessError:
                print("⚠️  Database might already exist or insufficient permissions")

    except FileNotFoundError:
        print("⚠️  PostgreSQL not found. Install PostgreSQL or use SQLite for development")

def setup_redis():
    """Setup Redis (optional - for development)"""
    print("🔴 Setting up Redis...")

    # Check if Redis is available
    try:
        result = subprocess.run(
            ["redis-cli", "ping"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and "PONG" in result.stdout:
            print("✅ Redis is running")
        else:
            print("⚠️  Redis is not running. Start Redis server or use memory caching")
    except FileNotFoundError:
        print("⚠️  Redis not found. Install Redis or use memory caching for development")

def run_tests():
    """Run the test suite"""
    print("🧪 Running tests...")

    test_file = Path(__file__).parent / "test_dashboard.py"
    if test_file.exists():
        try:
            subprocess.run([
                sys.executable, str(test_file)
            ], check=True)
            print("✅ All tests passed")
            return True
        except subprocess.CalledProcessError:
            print("❌ Some tests failed")
            return False
    else:
        print("⚠️  Test file not found, skipping tests")
        return True

def create_startup_script():
    """Create a startup script for the dashboard"""
    startup_script = Path(__file__).parent / "start_dashboard.sh"

    script_content = """#!/bin/bash
# Security Dashboard Startup Script

echo "🛡️  Starting Security Monitoring Dashboard..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Load environment variables
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Start the dashboard
echo "🚀 Starting dashboard server..."
python main.py

# Deactivate virtual environment on exit
deactivate
"""

    with open(startup_script, 'w') as f:
        f.write(script_content)

    # Make executable
    os.chmod(startup_script, 0o755)
    print(f"✅ Startup script created: {startup_script}")

def create_docker_files():
    """Create Docker configuration files"""
    # Dockerfile
    dockerfile = Path(__file__).parent / "Dockerfile"
    dockerfile_content = """FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN groupadd -r dashboard && useradd -r -g dashboard dashboard
RUN chown -R dashboard:dashboard /app
USER dashboard

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8080/api/health || exit 1

# Start command
CMD ["python", "main.py"]
"""

    with open(dockerfile, 'w') as f:
        f.write(dockerfile_content)

    # Docker Compose
    docker_compose = Path(__file__).parent / "docker-compose.yml"
    compose_content = """version: '3.8'

services:
  dashboard:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/security_dashboard
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=security_dashboard
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - dashboard
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
"""

    with open(docker_compose, 'w') as f:
        f.write(compose_content)

    print("✅ Docker files created")

def main():
    """Main setup function"""
    print("🛡️  Security Monitoring Dashboard Setup")
    print("=" * 50)

    # Step 1: Check Python version
    check_python_version()

    # Step 2: Create directories
    create_directories()

    # Step 3: Install dependencies
    if not install_dependencies():
        print("❌ Setup failed during dependency installation")
        sys.exit(1)

    # Step 4: Setup environment
    setup_environment()

    # Step 5: Validate configuration
    if not validate_configuration():
        print("❌ Setup failed during configuration validation")
        sys.exit(1)

    # Step 6: Setup database (optional)
    setup_database()

    # Step 7: Setup Redis (optional)
    setup_redis()

    # Step 8: Run tests
    if not run_tests():
        print("⚠️  Some tests failed, but continuing setup")

    # Step 9: Create startup script
    create_startup_script()

    # Step 10: Create Docker files
    create_docker_files()

    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next Steps:")
    print("1. Update .env file with your actual credentials")
    print("2. Configure config/security-dashboard.yml as needed")
    print("3. Start the dashboard:")
    print("   - Development: python main.py")
    print("   - Production: ./start_dashboard.sh")
    print("   - Docker: docker-compose up")
    print("4. Open browser: http://localhost:8080")
    print("\n📚 Documentation:")
    print("   - API Docs: http://localhost:8080/api/docs")
    print("   - Health Check: http://localhost:8080/api/health")

if __name__ == "__main__":
    main()