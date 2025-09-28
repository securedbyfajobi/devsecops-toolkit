#!/usr/bin/env python3
"""
Setup script for Container Security Scanner
Handles installation, configuration, and deployment
"""

import os
import sys
import subprocess
import shutil
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3.8, 0):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} detected")

def install_python_dependencies():
    """Install required Python dependencies"""
    print("📦 Installing Python dependencies...")

    requirements_file = Path(__file__).parent / "requirements.txt"
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False

    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
        ], check=True, capture_output=True)
        print("✅ Python dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Python dependencies: {e}")
        return False

def check_docker_installation():
    """Check if Docker is installed and accessible"""
    print("🐳 Checking Docker installation...")

    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"✅ Docker detected: {result.stdout.strip()}")

            # Test Docker daemon connectivity
            daemon_result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True
            )
            if daemon_result.returncode == 0:
                print("✅ Docker daemon is accessible")
                return True
            else:
                print("⚠️ Docker daemon is not accessible. Please start Docker.")
                return False
        else:
            print("❌ Docker not found")
            return False
    except FileNotFoundError:
        print("❌ Docker not found in PATH")
        return False

def install_trivy():
    """Install Trivy vulnerability scanner"""
    print("🔍 Installing Trivy scanner...")

    # Check if already installed
    try:
        result = subprocess.run(
            ["trivy", "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"✅ Trivy already installed: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass

    # Install based on platform
    system = platform.system().lower()
    machine = platform.machine().lower()

    try:
        if system == "linux":
            if machine in ["x86_64", "amd64"]:
                arch = "64bit"
            elif machine in ["aarch64", "arm64"]:
                arch = "ARM64"
            else:
                print(f"⚠️ Unsupported architecture: {machine}")
                return False

            # Download and install Trivy for Linux
            download_url = f"https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux-{arch}.tar.gz"
            subprocess.run([
                "curl", "-sfL", download_url, "|",
                "tar", "-xzC", "/usr/local/bin", "trivy"
            ], shell=True, check=True)

        elif system == "darwin":  # macOS
            # Use Homebrew if available
            try:
                subprocess.run(["brew", "install", "trivy"], check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("⚠️ Homebrew not found. Please install Trivy manually:")
                print("   brew install trivy")
                return False

        elif system == "windows":
            print("⚠️ Windows installation not automated. Please install Trivy manually:")
            print("   choco install trivy  # Using Chocolatey")
            print("   Or download from: https://github.com/aquasecurity/trivy/releases")
            return False

        else:
            print(f"⚠️ Unsupported platform: {system}")
            return False

        # Verify installation
        result = subprocess.run(["trivy", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Trivy installed successfully: {result.stdout.strip()}")
            return True
        else:
            print("❌ Trivy installation failed")
            return False

    except Exception as e:
        print(f"❌ Failed to install Trivy: {e}")
        return False

def install_grype():
    """Install Grype vulnerability scanner"""
    print("🔍 Installing Grype scanner...")

    # Check if already installed
    try:
        result = subprocess.run(
            ["grype", "version"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"✅ Grype already installed: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass

    # Install based on platform
    system = platform.system().lower()

    try:
        if system == "linux" or system == "darwin":
            # Use the official install script
            subprocess.run([
                "curl", "-sSfL", "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
                "|", "sh", "-s", "--", "-b", "/usr/local/bin"
            ], shell=True, check=True)

        elif system == "windows":
            print("⚠️ Windows installation not automated. Please install Grype manually:")
            print("   Download from: https://github.com/anchore/grype/releases")
            return False

        else:
            print(f"⚠️ Unsupported platform: {system}")
            return False

        # Verify installation
        result = subprocess.run(["grype", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Grype installed successfully")
            return True
        else:
            print("❌ Grype installation failed")
            return False

    except Exception as e:
        print(f"❌ Failed to install Grype: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    directories = [
        "config",
        "reports",
        "logs",
        "cache",
        "policies"
    ]

    for directory in directories:
        dir_path = Path(__file__).parent / directory
        dir_path.mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def setup_configuration():
    """Setup default configuration if not exists"""
    config_file = Path(__file__).parent / "config" / "container-security.yml"

    if not config_file.exists():
        print("⚠️ Configuration file not found. Please ensure config/container-security.yml exists")
        return False

    print("✅ Configuration file exists")
    return True

def validate_installation():
    """Validate the complete installation"""
    print("🧪 Validating installation...")

    # Test Python imports
    try:
        from container_scanner import ContainerSecurityScanner
        print("   ✓ Python modules importable")
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        return False

    # Test scanner initialization
    try:
        scanner = ContainerSecurityScanner()
        print("   ✓ Scanner initializes correctly")
    except Exception as e:
        print(f"   ❌ Scanner initialization failed: {e}")
        return False

    # Test external tools
    tools_status = []

    # Check Docker
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        tools_status.append(("Docker", True))
    except (subprocess.CalledProcessError, FileNotFoundError):
        tools_status.append(("Docker", False))

    # Check Trivy
    try:
        subprocess.run(["trivy", "--version"], capture_output=True, check=True)
        tools_status.append(("Trivy", True))
    except (subprocess.CalledProcessError, FileNotFoundError):
        tools_status.append(("Trivy", False))

    # Check Grype
    try:
        subprocess.run(["grype", "version"], capture_output=True, check=True)
        tools_status.append(("Grype", True))
    except (subprocess.CalledProcessError, FileNotFoundError):
        tools_status.append(("Grype", False))

    print("   📊 External tools status:")
    for tool, status in tools_status:
        status_icon = "✓" if status else "✗"
        print(f"      {status_icon} {tool}")

    # At least Docker and one scanner should be available
    docker_available = any(tool == "Docker" and status for tool, status in tools_status)
    scanner_available = any(tool in ["Trivy", "Grype"] and status for tool, status in tools_status)

    if docker_available and scanner_available:
        print("   ✅ Minimum requirements met")
        return True
    else:
        print("   ❌ Minimum requirements not met")
        return False

def run_test_scan():
    """Run a test scan to verify functionality"""
    print("🧪 Running test scan...")

    try:
        # Run a simple test using the test suite
        test_file = Path(__file__).parent / "test_container_scanner.py"
        if test_file.exists():
            result = subprocess.run([
                sys.executable, str(test_file)
            ], capture_output=True, text=True)

            if result.returncode == 0:
                print("✅ Test scan completed successfully")
                return True
            else:
                print(f"❌ Test scan failed: {result.stderr}")
                return False
        else:
            print("⚠️ Test file not found, skipping test scan")
            return True

    except Exception as e:
        print(f"❌ Test scan error: {e}")
        return False

def create_startup_scripts():
    """Create convenient startup scripts"""

    # Create shell script for Unix-like systems
    if platform.system() != "Windows":
        script_content = """#!/bin/bash
# Container Security Scanner Startup Script

echo "🛡️ Container Security Scanner"
echo "=============================="

# Check if virtual environment should be used
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
fi

# Update scanner databases
echo "🔄 Updating vulnerability databases..."
trivy image --download-db-only 2>/dev/null || echo "⚠️ Trivy DB update failed"
grype db update 2>/dev/null || echo "⚠️ Grype DB update failed"

# Run the scanner with provided arguments
python container-scanner.py "$@"

# Deactivate virtual environment if it was activated
if [ -d "venv" ]; then
    deactivate
fi
"""

        script_path = Path(__file__).parent / "scan.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)

        # Make executable
        os.chmod(script_path, 0o755)
        print(f"✅ Created startup script: {script_path}")

    # Create batch script for Windows
    batch_content = """@echo off
REM Container Security Scanner Startup Script

echo 🛡️ Container Security Scanner
echo ==============================

REM Check if virtual environment should be used
if exist "venv" (
    echo 📦 Activating virtual environment...
    call venv\\Scripts\\activate.bat
)

REM Update scanner databases
echo 🔄 Updating vulnerability databases...
trivy image --download-db-only >nul 2>&1 || echo ⚠️ Trivy DB update failed
grype db update >nul 2>&1 || echo ⚠️ Grype DB update failed

REM Run the scanner with provided arguments
python container-scanner.py %*

REM Deactivate virtual environment if it was activated
if exist "venv" (
    call venv\\Scripts\\deactivate.bat
)
"""

    batch_path = Path(__file__).parent / "scan.bat"
    with open(batch_path, 'w') as f:
        f.write(batch_content)
    print(f"✅ Created batch script: {batch_path}")

def main():
    """Main setup function"""
    print("🛡️ Container Security Scanner Setup")
    print("=" * 40)

    # Step 1: Check Python version
    check_python_version()

    # Step 2: Create directories
    create_directories()

    # Step 3: Install Python dependencies
    if not install_python_dependencies():
        print("❌ Setup failed during Python dependency installation")
        sys.exit(1)

    # Step 4: Check Docker
    docker_available = check_docker_installation()
    if not docker_available:
        print("⚠️ Docker not available. Some features may not work.")

    # Step 5: Install security scanners
    trivy_installed = install_trivy()
    grype_installed = install_grype()

    if not trivy_installed and not grype_installed:
        print("⚠️ No vulnerability scanners installed. Scanner will have limited functionality.")

    # Step 6: Setup configuration
    if not setup_configuration():
        print("❌ Setup failed during configuration")
        sys.exit(1)

    # Step 7: Validate installation
    if not validate_installation():
        print("❌ Installation validation failed")
        sys.exit(1)

    # Step 8: Run test scan
    if not run_test_scan():
        print("⚠️ Test scan failed, but continuing setup")

    # Step 9: Create startup scripts
    create_startup_scripts()

    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next Steps:")
    print("1. Test the scanner:")
    if platform.system() != "Windows":
        print("   ./scan.sh alpine:latest")
    else:
        print("   scan.bat alpine:latest")
    print("   OR")
    print("   python container-scanner.py alpine:latest")

    print("\n2. Customize configuration:")
    print("   Edit config/container-security.yml")

    print("\n3. Integration options:")
    print("   - Set environment variables for cloud credentials")
    print("   - Configure SIEM integrations")
    print("   - Set up CI/CD pipeline integration")

    print("\n📚 Documentation:")
    print("   - Configuration: config/container-security.yml")
    print("   - Test suite: python test_container_scanner.py")
    print("   - Help: python container-scanner.py --help")

if __name__ == "__main__":
    main()