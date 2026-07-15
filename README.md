# Certificate Tools Web Application

A comprehensive certificate management web application built with Flask that handles the complete certificate lifecycle from CSR generation to signing and format conversion.

## Features

### CSR Generation
- 🔐 Generate CSR and private key pairs
- 🔑 Support for multiple key sizes (2048, 3072, 4096 bits)
- 📋 Extended Key Usage (EKU) support with dropdown selection:
  - Server Authentication (serverAuth)
  - Client Authentication (clientAuth)
  - Code Signing (codeSigning)
  - Email Protection (emailProtection)
  - Time Stamping (timeStamping)
  - OCSP Signing (ocspSigning)
- ⚙️ Key usage extensions (digitalSignature, keyEncipherment)
- 📝 Configuration file support for default values
- ✅ All standard certificate fields supported

### Certificate Signing
- ✍️ Sign CSRs with your own CA certificate
- 🔏 Support for self-signed certificate generation
- 📅 Configurable validity period
- 🔐 Encrypted CA private key support
- ☁️ **Azure Key Vault Integration** - Sign CSRs using CA certificates stored in Azure Key Vault

### Format Conversion
- 🔄 Convert PEM to PFX (PKCS#12)
  - Combine private key and certificate
  - Optional certificate chain support
  - Password protection
- 🔄 Convert PFX to PEM
  - Extract private key, certificate, and chain
  - Support for password-protected PFX files
  - Individual component download

### User Interface
- 📝 Modern, responsive web interface
- 🎨 Professional Mosadex branding (anthracite/orange color scheme)
- 📱 Mobile-friendly with hamburger menu
- 🔀 Easy navigation with sidebar menu
- 📋 One-click copy to clipboard
- 💾 Download generated files

### Certificate/CSR Decoder
- 🔍 Decode and inspect CSR contents
- 📜 View certificate details and attributes
- 📋 Display subject, issuer, validity, extensions

### Certificate List
- 📑 List all certificates from Azure Key Vault
- 🔎 View certificate details and metadata
- ⬇️ Download certificates from Key Vault

### PKI mTLS Certificate Generation
- 🔐 Generate client certificates for mTLS authentication
- ☁️ Sign with CA from Azure Key Vault

## Requirements

- Python 3.11+
- Flask 3.1.3
- cryptography 49.0.0
- Werkzeug 3.1.8
- Gunicorn 26.0.0 (for production deployment)
- azure-identity 1.25.3+ (for Azure Key Vault integration)
- azure-keyvault-certificates 4.11.1+ (for Azure Key Vault integration)
- azure-keyvault-secrets 4.11.0+ (for Azure Key Vault integration)
- azure-storage-blob 12.30.0+ (for Azure Blob Storage integration)
- msal 1.37.0+ (for Microsoft authentication)
- flask-session 0.8.0+ (for server-side sessions)
- flask-wtf 1.3.0+ (for CSRF protection)
- python-dotenv 1.2.2+ (for environment configuration)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/gitsoep/certificate-tools.git
cd certificate-tools
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. **Configure Azure Authentication** (required for Azure Key Vault features):

   a. Create an Azure AD App Registration:
      - Go to [Azure Portal > Azure Active Directory > App registrations](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps)
      - Click "New registration"
      - Set name (e.g., "Certificate Tools")
      - Set redirect URI to `http://localhost:5001/auth/callback` (or your domain)
      - Click "Register"
   
   b. Configure API Permissions:
      - Go to "API permissions" in your app registration
      - Add "Azure Key Vault" > "user_impersonation" permission
      - Grant admin consent if you have admin rights
   
   c. Create Client Secret:
      - Go to "Certificates & secrets"
      - Create a new client secret and copy the value
   
   d. Create environment file:
      ```bash
      cp .env.example .env
      ```
      
   e. Edit `.env` and fill in your Azure AD app details:
      ```bash
      AZURE_CLIENT_ID=your-client-id-here
      AZURE_CLIENT_SECRET=your-client-secret-here
      AZURE_TENANT_ID=common
      FLASK_SECRET_KEY=your-generated-secret-key
      ```

4. **Important**: Add `.env` to `.gitignore` to protect your secrets!

5. **For Production/Reverse Proxy Deployments**:
   - The application is configured to work behind a reverse proxy (nginx, Apache, Traefik, etc.)
   - Supports X-Forwarded-* headers for proper HTTPS/host detection
   - OAuth callbacks will automatically use HTTPS when behind a proxy
   - See [REVERSE_PROXY_CONFIG.md](REVERSE_PROXY_CONFIG.md) for nginx, Apache, and Traefik examples
   - **Important**: Set your Azure AD redirect URI to your public HTTPS URL (e.g., `https://cert-tools.example.com/auth/callback`)


## Usage

### Development Mode

1. Start the Flask development server:
```bash
python run.py
```

### Production Mode

1. Using Gunicorn (recommended):
```bash
gunicorn --bind 0.0.0.0:5001 --workers 4 run:app
```

Or use the startup script:
```bash
chmod +x start.sh
./start.sh
```

2. Using Docker:
```bash
docker-compose up -d
```

3. **Behind a Reverse Proxy**:
   - Configure your reverse proxy (nginx, Apache, Traefik) to forward to port 5001
   - Ensure X-Forwarded-Host, X-Forwarded-Proto headers are set
   - See [REVERSE_PROXY_CONFIG.md](REVERSE_PROXY_CONFIG.md) for complete examples

The application will be available at `http://localhost:5001` (or your configured domain)

## Using the Application

### Generate CSR and Private Key

1. Navigate to the home page or "Generate CSR" menu item

2. Fill in the certificate details:
   - **Common Name (CN)** - Required (e.g., example.com or *.example.com)
   - **Organization (O)** - Your company name
   - **Organizational Unit (OU)** - Your department (e.g., IT)
   - **Country (C)** - Two-letter country code (e.g., NL)
   - **State/Province (ST)** - State or province name
   - **City/Locality (L)** - City name
   - **Email Address** - Contact email
   - **Extended Key Usage (EKU)** - Select the purpose of the certificate
   - **Key Size** - Choose 2048, 3072, or 4096 bits

3. Click "Generate CSR and Private Key"

4. Copy or download your private key and CSR

### Sign a CSR

1. Navigate to "Sign CSR" from the menu

2. Upload your CSR file

3. Set the validity period (in days)

4. Choose signing method:
   - **Self-signed**: Generate a self-signed certificate
   - **CA-signed**: Upload CA certificate and private key (with optional password)

5. Click "Sign CSR"

6. Download the signed certificate

### Sign a CSR with Azure Key Vault

**Important**: This feature requires Azure authentication. You must be logged in with your Azure account.

1. Click "Sign in with Azure" in the sidebar if not already logged in

2. Navigate to "Sign CSR (AKV)" from the menu

3. Provide your CSR (upload file or paste text)

4. Set the validity period (in days)

5. Select a CA certificate from the dropdown:
   - The application automatically loads all CA certificates from **all configured Key Vaults**
   - Each certificate shows its name and which Key Vault it comes from
   - Example: "MyCA (vault1)" indicates the certificate "MyCA" is in the "vault1" Key Vault

6. Click "Sign CSR with Azure Key Vault"

7. Download the signed certificate

**Configuration**: Set one or more Key Vault URLs in your environment:
```bash
# Single Key Vault
AZURE_KEYVAULT_URLS=https://my-keyvault.vault.azure.net/

# Multiple Key Vaults (comma-separated)
AZURE_KEYVAULT_URLS=https://vault1.vault.azure.net/,https://vault2.vault.azure.net/
```

**Note**: You must have appropriate permissions on all configured Key Vaults to access certificates and secrets. The application uses your Azure credentials to authenticate to each Key Vault. Certificates must have exportable private keys for signing operations.

### Convert PEM to PFX

1. Navigate to "PEM to PFX" from the menu

2. Upload your private key and certificate files

3. Optionally upload a chain certificate file

4. Enter a password for the PFX file

5. Click "Convert to PFX"

6. Download the generated PFX file

### Convert PFX to PEM

1. Navigate to "PFX to PEM" from the menu

2. Upload your PFX file

3. Enter the PFX password

4. Click "Convert to PEM"

5. Download the extracted private key, certificate, and chain (if present)

### Decode CSR or Certificate

1. Navigate to "Decoder" from the menu

2. Paste or upload your CSR or certificate in PEM format

3. Click "Decode"

4. View the decoded information including:
   - Subject details (CN, O, OU, etc.)
   - Public key information
   - Extensions and key usage
   - Validity period (for certificates)

### List Azure Key Vault Certificates

**Note**: Requires Azure authentication.

1. Navigate to "Certificate List" from the menu

2. The application loads certificates from all configured Key Vaults

3. View certificate details including name, vault, and expiration

4. Download certificates as needed

## Security Notes

⚠️ **Important**: 
- Keep your private keys secure and never share them with anyone
- Store private keys in a safe location - you'll need them when installing SSL certificates
- This application generates and processes keys locally and does not send any data to external servers
- Private keys and certificates are not stored on the server
- For production use, run the application over HTTPS
- Use strong passwords when creating PFX files
- When using CA signing, ensure your CA private key is properly secured

## Project Structure

```
certificate-tools/
├── run.py                      # Application entry point
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker container configuration
├── docker-compose.yml          # Docker Compose orchestration
├── start.sh                    # Production startup script
├── app/                        # Main application module
│   ├── __init__.py             # Flask application factory
│   ├── config.py               # Configuration settings
│   ├── routes/                 # Route blueprints
│   │   ├── main.py             # Home page routes
│   │   ├── auth.py             # Authentication routes
│   │   ├── csr.py              # CSR generation/signing routes
│   │   ├── decoder.py          # Certificate/CSR decoder routes
│   │   ├── converter.py        # Format conversion routes
│   │   └── azure.py            # Azure Key Vault routes
│   ├── services/               # Business logic services
│   │   ├── auth.py             # Authentication service
│   │   └── certificate.py      # Certificate operations
│   └── utils/                  # Utility modules
│       ├── credentials.py      # Azure credential handling
│       ├── decorators.py       # Route decorators
│       └── errors.py           # Error handlers
├── templates/                  # Jinja2 HTML templates
│   ├── index.html              # Home page
│   ├── login.html              # Azure login page
│   ├── sidebar.html            # Navigation sidebar
│   ├── csr_generator.html      # CSR generation form
│   ├── csr-generator-result.html  # CSR/Key results
│   ├── csr_signer.html         # CSR signing page
│   ├── csr_signer_akv.html     # Azure Key Vault CSR signing
│   ├── decoder.html            # CSR/Certificate decoder
│   ├── certificate_list.html   # Certificate list view
│   ├── pki_mtls.html           # mTLS certificate generation
│   ├── pfx_converter.html      # PEM to PFX converter
│   └── pfx_to_pem.html         # PFX to PEM converter
├── static/                     # Static assets
│   ├── tailwindcss.js          # CSS framework
│   ├── theme.js                # Theme handling
│   └── images/                 # Image assets
├── charts/                     # Helm charts for Kubernetes
│   └── certificate-tools/
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
├── .github/
│   ├── workflows/
│   │   ├── docker-publish.yml  # CI/CD pipeline for GHCR
│   │   └── codeql.yml          # Code security analysis
│   ├── dependabot.yml          # Dependency updates
│   └── codeql/
└── README.md                   # This file
```

## Docker Deployment

The application includes a production-ready Docker setup:

### Build and Run with Docker Compose

```bash
docker-compose up -d
```

### Build Manually

```bash
docker build -t certificate-tools:latest .
docker run -d -p 5001:5001 --name certificate-tools certificate-tools:latest
```

### Pull from GitHub Container Registry

```bash
docker pull ghcr.io/gitsoep/certificate-tools:main
docker run -d -p 5001:5001 ghcr.io/gitsoep/certificate-tools:main
```

### Kubernetes Deployment with Helm

The application includes Helm charts for Kubernetes deployment:

```bash
# Install from local charts
helm install certificate-tools ./charts/certificate-tools

# Install with custom values
helm install certificate-tools ./charts/certificate-tools -f custom-values.yaml

# Upgrade existing deployment
helm upgrade certificate-tools ./charts/certificate-tools
```

See [charts/certificate-tools/README.md](charts/certificate-tools/README.md) for detailed Helm configuration options.

## Configuration

Configuration is managed through environment variables. Create a `.env` file in the project root:

```bash
# Flask settings
FLASK_SECRET_KEY=your-secret-key-here

# Azure AD Configuration (required for Azure features)
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_TENANT_ID=common

# External URL (required when behind reverse proxy)
EXTERNAL_URL=https://your-domain.com

# Azure Key Vault URLs (comma-separated for multiple vaults)
AZURE_KEYVAULT_URLS=https://your-vault.vault.azure.net/

# Azure Blob Storage (optional)
AZURE_BLOB_STORAGE_URL=https://your-storage.blob.core.windows.net/
AZURE_BLOB_STORAGE_CONTAINER=storage

# Optional analytics snippet injected into the <head> of every page
ANALYTICS_HTML="<script>...</script>"

# Optional extra origin appended to the Content-Security-Policy connect-src directive
# (e.g. the endpoint used by your analytics script)
CONNECT_SRC=https://analytics.example.com

# CSR Generation Defaults
DEFAULT_COUNTRY=NL
DEFAULT_STATE=Gelderland
DEFAULT_LOCALITY=Nijmegen
DEFAULT_ORGANIZATION=Your Organization
DEFAULT_OU=Your Unit
DEFAULT_CN=example.com
DEFAULT_EMAIL=admin@example.com
DEFAULT_KEY_SIZE=4096

# Logging
LOG_LEVEL=WARNING
```

## How It Works

### CSR Generation
1. The application uses the `cryptography` library to generate RSA private keys
2. A Certificate Signing Request is created with the provided subject information
3. Key usage and extended key usage extensions are added based on selection
4. Both the private key and CSR are serialized to PEM format
5. The results are displayed in the browser with options to copy or download

### CSR Signing
1. The CSR is parsed and validated
2. A new certificate is created with the CSR's public key and subject
3. If CA signing is selected, the certificate is signed with the CA's private key
4. If self-signing is selected, the certificate is signed with the CSR's private key
5. The signed certificate is returned in PEM format

### CSR/Certificate Decoding
1. The CSR or certificate PEM content is parsed
2. Subject, issuer, validity, and extensions are extracted
3. Details are formatted and displayed in a readable format
4. Useful for inspecting certificate contents before deployment

### PEM to PFX Conversion
1. Private key and certificate files are parsed
2. Optional chain certificates are included
3. All components are packaged into a PKCS#12 (PFX) file
4. The PFX is password-protected with the specified password

### PFX to PEM Conversion
1. The PFX file is decrypted using the provided password
2. Private key, certificate, and chain certificates are extracted
3. Each component is serialized to PEM format
4. Results are displayed with individual download options

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
