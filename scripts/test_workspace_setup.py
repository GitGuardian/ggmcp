#!/usr/bin/env python3
"""
Test script to verify the workspace structure and dependencies are set up correctly.
This script attempts to import from each package to verify they can be found,
and also checks for required dependencies.
"""

import importlib
import os
import sys
from pathlib import Path


def add_workspace_to_path():
    """Add the workspace packages to the Python path."""
    repo_root = Path(__file__).parent.parent.resolve()
    packages_dir = repo_root / "packages"

    # Print Python environment info for debugging
    print("\n== Python Environment Info ==")
    print(f"Python executable: {sys.executable}")
    print(f"Python version: {sys.version}")
    print(f"sys.path: {sys.path}")

    # Check for virtual environment
    venv_path = os.environ.get("VIRTUAL_ENV")
    if venv_path:
        print(f"Virtual environment: {venv_path}")
    else:
        print("Not running in a virtual environment")

    # Add each package's src directory to the path
    for package_dir in packages_dir.iterdir():
        if package_dir.is_dir():
            src_dir = package_dir / "src"
            if src_dir.exists():
                sys.path.insert(0, str(src_dir))
                print(f"Added {src_dir} to Python path")


def check_dependencies():
    """Check if required dependencies are installed."""
    required_deps = [
        "mcp",
        "httpx",
        "pydantic",
    ]

    missing_deps = []

    print("\n== Checking Dependencies ==")
    for dep in required_deps:
        try:
            module = importlib.import_module(dep)
            print(f"✅ Dependency {dep} is installed (version: {getattr(module, '__version__', 'unknown')})")
        except ImportError:
            print(f"❌ Dependency {dep} is missing")
            missing_deps.append(dep)

    if missing_deps:
        print("\n⚠️  Missing dependencies detected. Please install them with:")
        print("uv sync")
        print("or")
        print(f"uv pip install {' '.join(missing_deps)}")

        # Try to help with troubleshooting
        print("\nTroubleshooting suggestions:")
        print("1. Make sure you're running this script in the correct virtual environment")
        print("2. Check if dependencies are installed with: uv pip list")
        print("3. Try installing the dependencies manually: uv pip install mcp httpx pydantic")

    return missing_deps


def test_imports():
    """Test importing key modules from each package."""
    import_tests = [
        # Core package
        ("gg_api_core", ["gg_api_core.client", "gg_api_core.mcp_server", "gg_api_core.utils", "gg_api_core.oauth"]),
        # Developer MCP server
        ("developer_mcp_server", ["developer_mcp_server.server"]),
        # SecOps MCP server
        ("secops_mcp_server", ["secops_mcp_server.server"]),
    ]

    failures = []

    for package_name, modules in import_tests:
        print(f"\n== Testing {package_name} ==")

        try:
            # First check if the base package can be imported
            importlib.import_module(package_name)
            print(f"✅ Successfully imported {package_name}")

            # Then check each module
            for module in modules:
                try:
                    importlib.import_module(module)
                    print(f"✅ Successfully imported {module}")
                except ImportError as e:
                    print(f"❌ Failed to import {module}: {e}")
                    failures.append((module, str(e)))
        except ImportError as e:
            print(f"❌ Failed to import {package_name}: {e}")
            failures.append((package_name, str(e)))

    return failures


def test_server_classes():
    """Test creating instances of the server classes."""
    print("\n== Testing server classes ==")

    try:
        from gg_api_core.mcp_server import GitGuardianFastMCP

        # Just instantiate the class to test it
        get_mcp_server("Test Core")
        print("✅ Successfully created GitGuardianFastMCP instance")
    except Exception as e:
        print(f"❌ Failed to create GitGuardianFastMCP instance: {e}")
        return False

    try:
        # Import the server module (with its mcp instance)
        print("✅ Successfully imported developer MCP server module")
    except Exception as e:
        print(f"❌ Failed to import developer MCP server module: {e}")
        return False

    try:
        # Import the server module (with its mcp instance)
        print("✅ Successfully imported SecOps MCP server module")
    except Exception as e:
        print(f"❌ Failed to import SecOps MCP server module: {e}")
        return False

    return True


def verify_package_structure():
    """Verify that the package structure is correct."""
    repo_root = Path(__file__).parent.parent.resolve()

    print("\n== Verifying Package Structure ==")

    # Define expected structure
    expected_packages = ["gg_api_core", "developer_mcp_server", "secops_mcp_server"]
    expected_files = {
        "gg_api_core": ["client.py", "mcp_server.py", "utils.py", "oauth.py"],
        "developer_mcp_server": ["server.py"],
        "secops_mcp_server": ["server.py"],
    }

    all_found = True

    # Check each package
    for package in expected_packages:
        package_dir = repo_root / "packages" / package / "src" / package
        if not package_dir.exists():
            print(f"❌ Package directory {package_dir} not found")
            all_found = False
            continue

        print(f"✅ Package directory {package} found")

        # Check expected files in package
        for file in expected_files.get(package, []):
            file_path = package_dir / file
            if not file_path.exists():
                print(f"❌ Expected file {file} not found in {package}")
                all_found = False
            else:
                print(f"✅ Found expected file {file} in {package}")

    return all_found


def main():
    """Run the workspace tests."""
    print("== GitGuardian MCP Server Workspace Test ==")
    add_workspace_to_path()

    # Check package structure first
    structure_ok = verify_package_structure()

    # Check dependencies
    missing_deps = check_dependencies()

    # Only run import tests if there are no missing dependencies
    if not missing_deps:
        import_failures = test_imports()
        server_success = test_server_classes()
    else:
        import_failures = ["Skipped due to missing dependencies"]
        server_success = False

    print("\n== Test Summary ==")
    if structure_ok:
        print("✅ Package structure is correct")
    else:
        print("❌ Package structure has issues")

    if missing_deps:
        print("❌ Some dependencies are missing - install them before running further tests")
    else:
        print("✅ All dependencies are installed")

    if not import_failures or import_failures == ["Skipped due to missing dependencies"]:
        if not missing_deps:
            print("✅ All imports successful")
    else:
        print("❌ Some imports failed")

    if server_success:
        print("✅ Server classes tests passed")
    elif not missing_deps:
        print("❌ Server classes tests failed")

    if structure_ok and not missing_deps and not import_failures and server_success:
        print("\n✅ All tests passed! Your workspace setup is correct.")
        return 0
    elif structure_ok and missing_deps:
        print("\n⚠️ The package structure looks good, but you need to install dependencies.")
        print("Run the following command to install all required dependencies:")
        print("uv sync")
        print("\nMake sure you're activating the correct virtual environment:")
        print("source .venv/bin/activate  # Or your virtual environment path")
        return 1
    else:
        print("\n❌ Some tests failed. Please check the output above for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
