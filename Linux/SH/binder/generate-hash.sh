#!/bin/bash
# axon | AU

echo "Bind Shell Password Hash Generator"

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    echo "ERROR: openssl is not installed"
    echo "Please install openssl: sudo apt-get install openssl"
    exit 1
fi

# Get password
echo -n "Enter password: "
read -s password
echo ""

if [ -z "$password" ]; then
    echo "ERROR: Password cannot be empty"
    exit 1
fi

# Generate random salt
salt=$(openssl rand -base64 16 | tr -d '/+=' | cut -c1-16)

echo ""
echo "Generating SHA-512 hash with random salt..."
echo ""

# Generate hash
hash=$(openssl passwd -6 -salt "$salt" "$password")

echo "Generated Password Hash:"
echo "========================"
echo "$hash"
echo ""
echo "Add this to your bind-shell.service file:"
echo 'Environment="PASSWORD_HASH='"$hash"'"'
echo ""

# Test verification
echo "Testing hash verification..."
test_hash=$(openssl passwd -6 -salt "$salt" "$password")
if [ "$hash" = "$test_hash" ]; then
    echo "✓ Hash verification successful!"
else
    echo "✗ Hash verification failed!"
fi
echo ""

# Show SHA-256 alternative
echo "Alternative SHA-256 hash (simpler, less secure):"
sha256_hash=$(echo -n "$password" | openssl dgst -sha256 -hex | awk '{print $2}')
echo "$sha256_hash"
