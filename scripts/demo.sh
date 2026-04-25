#!/bin/bash
# SentinelCI Demo Script
# This script demonstrates the capabilities of SentinelCI

set -e

echo "🎬 SentinelCI Demo"
echo "=================="
echo ""

# Setup
echo "Setting up demo environment..."
DEMO_DIR="/tmp/sentinelci-demo"
mkdir -p "$DEMO_DIR/vulnerable-code"
cd "$DEMO_DIR"

# Create vulnerable code samples
cat > vulnerable-code/secrets.py << 'EOF'
# Example Python file with hardcoded secrets
import requests

API_KEY = "sk-abc123def456ghi789"  # This is a fake secret for demo
DB_PASSWORD = "super_secret_password_123"

def authenticate():
    headers = {
        "Authorization": f"Bearer {API_KEY}"
    }
    return headers
EOF

cat > vulnerable-code/suspicious_urls.py << 'EOF'
# Example with suspicious Unicode domains
CONFIG = {
    "api_endpoint": "https://api-cdn.com/v1",  # Looks normal but has Cyrillic characters hidden
    "backup_endpoint": "https://backup.example.com",
}
EOF

cat > vulnerable-code/vulnerable_component.txt << 'EOF'
This sample mentions OpenSSL and other components
that might have known CVEs.
EOF

# Run SentinelCI
echo ""
echo "📁 Created vulnerable code samples in: $DEMO_DIR/vulnerable-code"
echo ""
echo "Running SentinelCI scan..."
echo ""

# This would run sentinelci if it were installed globally
# sentinelci scan --target vulnerable-code --format terminal

echo ""
echo "✅ Demo complete!"
echo ""
echo "Next steps:"
echo "  1. Install sentinelci: pip install -e ."
echo "  2. Configure API key: sentinelci config"
echo "  3. Run scan: sentinelci scan --target $DEMO_DIR/vulnerable-code"
echo "  4. Review findings and remediation steps"
echo ""
