import sys
import os

def check_python_version():
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print("✓ Python version:", f"{version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print("✗ Python 3.8+ required. Current:", f"{version.major}.{version.minor}.{version.micro}")
        return False

def check_dependencies():
    required = ['flask', 'numpy', 'pandas', 'sklearn', 'requests']
    missing = []
    
    for package in required:
        try:
            __import__(package)
            print(f"✓ {package} installed")
        except ImportError:
            print(f"✗ {package} missing")
            missing.append(package)
    
    return len(missing) == 0

def check_directory_structure():
    required_dirs = [
        'core/normalization',
        'core/correlation',
        'core/alert_manager',
        'core/ml_detection',
        'core/incident_response',
        'web/templates',
        'web/static/css',
        'web/static/js',
        'config',
        'data/logs',
        'data/rules'
    ]
    
    all_exist = True
    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            print(f"✓ {dir_path}")
        else:
            print(f"✗ {dir_path} missing")
            all_exist = False
    
    return all_exist

def check_files():
    required_files = [
        'app.py',
        'requirements.txt',
        'core/normalization/normalizer.py',
        'core/correlation/engine.py',
        'core/alert_manager/manager.py',
        'core/ml_detection/anomaly_detector.py',
        'core/incident_response/responder.py',
        'web/templates/dashboard.html',
        'web/static/js/dashboard.js',
        'web/static/css/style.css',
        'config/settings.py'
    ]
    
    all_exist = True
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path} missing")
            all_exist = False
    
    return all_exist

def main():
    print("=" * 60)
    print("SOC Platform - Setup Verification")
    print("=" * 60)
    
    print("\n1. Checking Python Version...")
    python_ok = check_python_version()
    
    print("\n2. Checking Dependencies...")
    deps_ok = check_dependencies()
    
    print("\n3. Checking Directory Structure...")
    dirs_ok = check_directory_structure()
    
    print("\n4. Checking Required Files...")
    files_ok = check_files()
    
    print("\n" + "=" * 60)
    if python_ok and deps_ok and dirs_ok and files_ok:
        print("✓ ALL CHECKS PASSED!")
        print("\nYou're ready to start the platform:")
        print("  python app.py")
        print("\nOr use the quick start:")
        print("  start.bat")
    else:
        print("✗ SOME CHECKS FAILED")
        print("\nPlease fix the issues above before starting.")
        if not deps_ok:
            print("\nTo install dependencies:")
            print("  pip install -r requirements.txt")
    print("=" * 60)

if __name__ == "__main__":
    main()
