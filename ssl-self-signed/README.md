# SSL Certificate Generation

This directory contains scripts for generating self-signed SSL certificates for BillionMail.

## Important Security Notice

**Never commit private keys or certificates to version control!**

The `.pem` files in this directory are ignored by git to prevent accidental exposure of sensitive credentials.

## Generating SSL Certificates

To generate a new self-signed SSL certificate, run:

```bash
./generate-ssl-cert.sh
```

This will create:
- `key.pem` - Private key (keep this secret!)
- `cert.pem` - Self-signed certificate

## Production Use

For production environments, it is strongly recommended to use certificates from a trusted Certificate Authority (CA) instead of self-signed certificates.
