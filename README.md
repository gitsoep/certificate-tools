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

## Requirements

- Python 3.11+
- Flask 3.0.0
- cryptography 41.0.7
- Gunicorn 21.2.0 (for production deployment)
- azure-identity 1.15.0+ (for Azure Key Vault integration)
- azure-keyvault-certificates 4.8.0+ (for Azure Key Vault integration)
- azure-keyvault-secrets 4.8.0+ (for Azure Key Vault integration)

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


## Usage

### Development Mode

1. Start the Flask development server:
```bash
python app.py
```

### Production Mode

1. Using Gunicorn (recommended):
```bash
gunicorn --bind 0.0.0.0:5001 --workers 4 app:app
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

The application will be available at `http://localhost:5001`

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

5. Configure Azure Key Vault:
   - **Key Vault URL**: Your Azure Key Vault URL (e.g., https://my-keyvault.vault.azure.net/)
   - **Certificate Name**: The name of the CA certificate stored in the Key Vault

6. Click "Sign CSR with Azure Key Vault"

7. Download the signed certificate

**Note**: You must have appropriate permissions on the Azure Key Vault to access certificates and secrets. The application uses your Azure credentials to authenticate to Key Vault.

6. Click "Sign CSR with Azure Key Vault"

7. Download the signed certificate

**Note**: The certificate in Azure Key Vault must have an exportable private key for signing operations.

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
├── app.py                      # Main Flask application
├── csr.conf                    # Default configuration values
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker container configuration
├── docker-compose.yml          # Docker Compose orchestration
├── .github/
│   └── workflows/
│       └── docker-publish.yml  # CI/CD pipeline for GHCR
├── README.md                   # This file
└── templates/    ├── csr_signer_akv.html     # Azure Key Vault CSR signing page    ├── index.html              # CSR generation form
    ├── result.html             # CSR/Key results display
    ├── csr_signer.html         # CSR signing page
    ├── pfx_converter.html      # PEM to PFX converter
    └── pfx_to_pem.html         # PFX to PEM converter
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

## Configuration

Default values for CSR generation can be customized in `csr.conf`:

```ini
[req]
default_bits = 4096
distinguished_name = req_distinguished_name

[req_distinguished_name]
C = NL
ST = Gelderland
L = Nijmegen
O = Mosadex Services B.V.
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
