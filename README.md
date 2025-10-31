# CertGen - Certificate Generator

CertGen is a web-based tool for generating X.509 certificates for development and testing purposes. It provides an easy-to-use interface for creating Certificate Authority (CA) certificates and client/server certificates signed by a CA.

## Features

- Generate Certificate Authority (CA) certificates
- Generate server certificates with DNS and IP address SANs
- Generate client certificates
- All certificates use ECDSA with P-384 curve for strong security
- Configurable certificate attributes:
  - Organization
  - Common Name
  - Country
  - Locality
  - Expiry period (in days)
- Downloads certificates in ZIP format containing:
  - Separate certificate file (`.crt`)
  - Separate private key file (`.key`)
  - Unified PEM file containing both certificate and private key (`.pem`)

## Usage

1. Start the server:
   ```bash
   go run main.go
   ```
   The server will start on `localhost:9595` by default.

2. Open your web browser and navigate to `http://localhost:9595`

3. Generate certificates:
   - First, create a CA certificate
   - Download and save the CA certificate files
   - Use the CA to sign new server or client certificates

### Generating a CA Certificate

1. Fill in the CA certificate details:
   - Organization (e.g., "My Company")
   - Common Name (e.g., "My Company Root CA")
   - Country (e.g., "US")
   - Locality (e.g., "San Francisco")
   - Expiry Days (e.g., 365)

2. Click "Generate CA" to create and download the CA certificate files

### Generating Server/Client Certificates

1. Upload your CA certificate (`.crt`) and private key (`.key`) files

2. Fill in the certificate details:
   - Organization
   - Common Name (hostname for servers, username for clients)
   - Country
   - Locality
   - Expiry Days
   - Certificate Type (Server or Client)
   - DNS Names (for server certificates)
   - IP Addresses (for server certificates)

3. Click "Generate Certificate" to create and download the certificate files

## Certificate File Formats

The generated certificates are provided in multiple formats:

### For CA Certificates:
- `ca.crt` - The CA certificate in PEM format
- `ca.key` - The CA private key in PEM format
- `ca.pem` - A unified file containing both the CA certificate and private key

### For Client/Server Certificates:
- `[client|server].crt` - The leaf certificate in PEM format
- `[client|server].key` - The private key in PEM format
- `[client|server].pem` - A unified file containing both the leaf certificate and private key
- `[client|server]-chain.pem` - Certificate chain containing the leaf certificate followed by the CA certificate (useful for validation)
- `[client|server]-fullchain.pem` - Full chain containing the leaf certificate, CA certificate, and private key (convenient for some mTLS configurations)

### When to Use Each Format

- **`.crt` and `.key`**: When you need separate certificate and key files (common in many server configurations)
- **`.pem`**: When you need certificate and key in a single file (convenient for many applications)
- **`-chain.pem`**: When you need to present the full certificate chain for validation (required by some TLS clients)
- **`-fullchain.pem`**: When you need everything in one file - certificate chain and private key (useful for some mTLS setups and load balancers)

### Example Use Cases

**Using chain files with curl:**
```bash
# Client authentication with full chain
curl --cert client-fullchain.pem --cacert ca.crt https://example.com

# Server verification with chain
curl --cert client.pem --cacert server-chain.pem https://example.com
```

**Using with nginx:**
```nginx
ssl_certificate /path/to/server-chain.pem;
ssl_certificate_key /path/to/server.key;
```

## Security Considerations

- This tool is intended for development and testing purposes
- Do not use generated certificates in production environments
- Keep private keys secure and never share them
- CA private keys are particularly sensitive as they can be used to sign new certificates

## Development

### Building from Source

```bash
git clone https://github.com/pvormste/certgen.git
cd certgen
go build
```

### Project Structure

```
certgen/
├── assets/
│   ├── static/   # Static web assets
│   └── templates/ # HTML templates
├── internal/
│   ├── certificate/ # Certificate generation logic
│   └── server/     # HTTP server implementation
└── main.go        # Application entry point
```
