#!/bin/bash
# Generate self-signed SSL certificate for BillionMail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Generate private key
openssl genrsa -out key.pem 2048

# Generate self-signed certificate
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Set appropriate permissions
chmod 600 key.pem
chmod 644 cert.pem

echo "Self-signed SSL certificate generated successfully!"
echo "Private key: $SCRIPT_DIR/key.pem"
echo "Certificate: $SCRIPT_DIR/cert.pem"
