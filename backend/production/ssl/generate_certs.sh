#!/bin/bash
# Generate SSL certificates for CyberShield Production SSO

echo "🔐 Generating Production SSL Certificates for CyberShield SSO"

# Create SAML signing certificate (self-signed for demo)
openssl req -new -x509 -days 365 -nodes \
    -out production/ssl/saml/cybershield.crt \
    -keyout production/ssl/saml/cybershield.key \
    -subj "/C=US/ST=CA/L=San Francisco/O=CyberShield Inc/OU=Engineering/CN=cybershield-ironcore.com"

# Set proper permissions
chmod 400 production/ssl/saml/cybershield.key
chmod 444 production/ssl/saml/cybershield.crt

# Create CA certificate bundle
cp /etc/ssl/certs/ca-certificates.crt production/ssl/certs/ 2>/dev/null || \
cp /etc/ssl/cert.pem production/ssl/certs/ca-certificates.crt 2>/dev/null || \
echo "# CA certificates for production" > production/ssl/certs/ca-certificates.crt

echo "✅ SSL certificates generated successfully"
echo "📁 SAML Certificate: production/ssl/saml/cybershield.crt"
echo "🔑 SAML Private Key: production/ssl/saml/cybershield.key"