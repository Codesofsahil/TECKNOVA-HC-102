import sys

print("=" * 60)
print("SOC Platform - Status Check")
print("=" * 60)

# Check Python version
version = sys.version_info
print(f"\nPython Version: {version.major}.{version.minor}.{version.micro}")
if version.major >= 3 and version.minor >= 7:
    print("Status: OK (Python 3.7+)")
else:
    print("Status: WARNING (Python 3.8+ recommended)")

# Check imports
print("\nChecking imports...")
try:
    from flask import Flask
    print("  Flask: OK")
except:
    print("  Flask: MISSING - Run: pip install Flask")

try:
    from core.enhanced_services import NotificationManager
    print("  Enhanced Services: OK")
except Exception as e:
    print(f"  Enhanced Services: ERROR - {e}")

try:
    from core.normalization.normalizer import LogNormalizer
    print("  Core Modules: OK")
except Exception as e:
    print(f"  Core Modules: ERROR - {e}")

# Check files
print("\nChecking key files...")
import os
files = [
    'app.py',
    'core/enhanced_services.py',
    'web/templates/dashboard.html',
    'config/settings.py'
]

for f in files:
    if os.path.exists(f):
        print(f"  {f}: OK")
    else:
        print(f"  {f}: MISSING")

print("\n" + "=" * 60)
print("Status Check Complete!")
print("=" * 60)
print("\nTo start the platform:")
print("  python app.py")
print("\nDashboard will be at:")
print("  http://localhost:5000")
