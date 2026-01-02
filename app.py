from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import configparser
import os
import msal
import uuid
from dotenv import load_dotenv
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())
app.config['SESSION_TYPE'] = 'filesystem'

# Configure proxy support - trust X-Forwarded-* headers
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

Session(app)

# Azure AD Configuration
CLIENT_ID = os.environ.get('AZURE_CLIENT_ID')
CLIENT_SECRET = os.environ.get('AZURE_CLIENT_SECRET')
TENANT_ID = os.environ.get('AZURE_TENANT_ID', 'common')
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_PATH = "/auth/callback"
SCOPE = ["https://vault.azure.net/.default"]

# External URL for OAuth callbacks (when behind reverse proxy)
# Example: https://certificate-tools.soep.org
EXTERNAL_URL = os.environ.get('EXTERNAL_URL', '').rstrip('/')

# Application title
APP_TITLE = os.environ.get('APP_TITLE', 'Certificate Tools')

# Azure Blob Storage Configuration
AZURE_BLOB_STORAGE_URL = os.environ.get('AZURE_BLOB_STORAGE_URL', '').rstrip('/')
AZURE_BLOB_STORAGE_CONTAINER = os.environ.get('AZURE_BLOB_STORAGE_CONTAINER', 'storage')

def _build_msal_app(cache=None, authority=None):
    """Build a confidential client application for MSAL"""
    return msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=authority or AUTHORITY,
        client_credential=CLIENT_SECRET,
        token_cache=cache
    )

def _build_auth_url(authority=None, scopes=None, state=None):
    """Build the authorization URL for user login"""
    if EXTERNAL_URL:
        redirect_uri = f"{EXTERNAL_URL}{REDIRECT_PATH}"
    else:
        redirect_uri = url_for("authorized", _external=True)
    
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=redirect_uri
    )

def _get_token_from_cache(scope=None):
    """Get token from the session cache"""
    cache = _load_cache()
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:
        result = cca.acquire_token_silent(scope or SCOPE, account=accounts[0])
        _save_cache(cache)
        return result
    return None

def _load_cache():
    """Load the token cache from session"""
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache

def _save_cache(cache):
    """Save the token cache to session"""
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()

def login_required(f):
    """Decorator to require Azure login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def load_config_defaults():
    defaults = {
        'country': os.environ.get('DEFAULT_COUNTRY', 'NL'),
        'state': os.environ.get('DEFAULT_STATE', 'Gelderland'),
        'locality': os.environ.get('DEFAULT_LOCALITY', 'Nijmegen'),
        'organization': os.environ.get('DEFAULT_ORGANIZATION', 'Soep Org'),
        'organizational_unit': os.environ.get('DEFAULT_OU', 'Example Unit'),
        'common_name': os.environ.get('DEFAULT_CN', 'Soep Example'),
        'email': os.environ.get('DEFAULT_EMAIL', 'example@gitsoep.nl'),
        'key_size': os.environ.get('DEFAULT_KEY_SIZE', '4096')
    }
    return defaults

CONFIG_DEFAULTS = load_config_defaults()

@app.route('/')
def index():
    user = session.get("user")
    return render_template('index.html', active_page='home', user=user, app_title=APP_TITLE)

@app.route('/login')
def login():
    """Redirect user to Azure AD login page"""
    # Clear any existing session
    session.clear()
    # Build authentication URL
    auth_url = _build_auth_url(scopes=SCOPE)
    return redirect(auth_url)

@app.route('/auth/callback')
def authorized():
    """Handle the redirect from Azure AD after authentication"""
    if request.args.get('state'):
        cache = _load_cache()
        
        if EXTERNAL_URL:
            redirect_uri = f"{EXTERNAL_URL}{REDIRECT_PATH}"
        else:
            redirect_uri = url_for('authorized', _external=True)
        
        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=SCOPE,
            redirect_uri=redirect_uri
        )
        
        if "error" in result:
            return render_template('login.html', error=result.get("error_description"), app_title=APP_TITLE)
        
        if "access_token" in result:
            # Save user info to session
            session["user"] = result.get("id_token_claims")
            _save_cache(cache)
        
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Log out the current user"""
    session.clear()
    
    if EXTERNAL_URL:
        post_logout_uri = EXTERNAL_URL
    else:
        post_logout_uri = url_for("index", _external=True)
    
    return redirect(
        AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + post_logout_uri
    )


@app.route('/csr-generator')
def csr_generator():
    user = session.get("user")
    return render_template('csr_generator.html', defaults=CONFIG_DEFAULTS, active_page='csr-generator', user=user, app_title=APP_TITLE)

@app.route('/generate', methods=['POST'])
def generate_csr():
    try:
        # Get form data with config defaults as fallback
        country = request.form.get('country', CONFIG_DEFAULTS['country'])
        state = request.form.get('state', CONFIG_DEFAULTS['state'])
        locality = request.form.get('locality', CONFIG_DEFAULTS['locality'])
        organization = request.form.get('organization', CONFIG_DEFAULTS['organization'])
        organizational_unit = request.form.get('organizational_unit', CONFIG_DEFAULTS['organizational_unit'])
        common_name = request.form.get('common_name', CONFIG_DEFAULTS['common_name'])
        email = request.form.get('email', CONFIG_DEFAULTS['email'])
        key_option = request.form.get('key_option', 'generate')
        eku_selection = request.form.get('eku', 'clientAuth')  # Get single EKU selection

        # Validate required fields
        if not common_name:
            return jsonify({'error': 'Common Name is required'}), 400

        # Handle private key - either generate new or use existing
        if key_option == 'existing':
            # Use existing private key
            key_input_method = request.form.get('key_input_method', 'paste')
            
            if key_input_method == 'paste':
                # Get private key from text input
                private_key_text = request.form.get('private_key_text', '').strip()
                if not private_key_text:
                    return jsonify({'error': 'Private key text is required when using existing key'}), 400
                
                try:
                    private_key_data = private_key_text.encode('utf-8')
                    private_key = serialization.load_pem_private_key(
                        private_key_data,
                        password=None,
                        backend=default_backend()
                    )
                except Exception as e:
                    return jsonify({'error': f'Invalid private key: {str(e)}'}), 400
            else:
                # Get private key from file upload
                private_key_file = request.files.get('private_key_file')
                if not private_key_file:
                    return jsonify({'error': 'Private key file is required when using file upload'}), 400
                
                try:
                    private_key_data = private_key_file.read()
                    private_key = serialization.load_pem_private_key(
                        private_key_data,
                        password=None,
                        backend=default_backend()
                    )
                except Exception as e:
                    return jsonify({'error': f'Invalid private key file: {str(e)}'}), 400
        else:
            # Generate new private key
            key_size = int(request.form.get('key_size', CONFIG_DEFAULTS['key_size']))
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )

        # Build subject attributes
        subject_attrs = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ]
        
        if state:
            subject_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            subject_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if organization:
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if organizational_unit:
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
        
        subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        
        if email:
            subject_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        # Build CSR with extensions
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(subject_attrs)
        )
        
        # Add key usage extensions
        csr_builder = csr_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Add extended key usage based on selection
        eku_map = {
            'serverAuth': x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            'clientAuth': x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            'codeSigning': x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
            'emailProtection': x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
            'timeStamping': x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
            'ocspSigning': x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING
        }
        
        if eku_selection in eku_map:
            csr_builder = csr_builder.add_extension(
                x509.ExtendedKeyUsage([eku_map[eku_selection]]),
                critical=False
            )
        
        # Generate CSR
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

        # Serialize CSR to PEM format
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        # Determine if we should show the private key (only if it was newly generated)
        show_private_key = (key_option != 'existing')
        
        if show_private_key:
            # Serialize private key to PEM format
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            return render_template('csr-generator-result.html', 
                                 private_key=private_key_pem, 
                                 csr=csr_pem,
                                 show_private_key=True,
                                 user=session.get("user"),
                                 app_title=APP_TITLE)
        else:
            return render_template('csr-generator-result.html', 
                                 csr=csr_pem,
                                 show_private_key=False,
                                 user=session.get("user"),
                                 app_title=APP_TITLE)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/pfx-converter')
def pfx_converter():
    user = session.get("user")
    return render_template('pfx_converter.html', active_page='pfx-converter', user=user, app_title=APP_TITLE)

@app.route('/csr-signer')
def csr_signer():
    user = session.get("user")
    return render_template('csr_signer.html', active_page='csr-signer', user=user, app_title=APP_TITLE)

@app.route('/csr-signer-akv')
@login_required
def csr_signer_akv():
    user = session.get("user")
    default_vault_url = os.environ.get('DEFAULT_KEYVAULT_URL', '')
    return render_template('csr_signer_akv.html', active_page='csr-signer-akv', user=user, default_vault_url=default_vault_url, app_title=APP_TITLE)

@app.route('/pfx-to-pem')
def pfx_to_pem():
    user = session.get("user")
    return render_template('pfx_to_pem.html', active_page='pfx-to-pem', user=user, app_title=APP_TITLE)

@app.route('/csr-decoder')
def csr_decoder():
    user = session.get("user")
    return render_template('csr_decoder.html', active_page='csr-decoder', user=user, app_title=APP_TITLE)

@app.route('/certificate-list')
@login_required
def certificate_list():
    user = session.get("user")
    return render_template('certificate_list.html', active_page='certificate-list', user=user, app_title=APP_TITLE)

@app.route('/pki')
@login_required
def pki():
    user = session.get("user")
    default_vault_url = os.environ.get('DEFAULT_KEYVAULT_URL', '')
    return render_template(
        'pki.html',
        active_page='pki',
        user=user,
        default_vault_url=default_vault_url,
        app_title=APP_TITLE
    )

@app.route('/decode-csr', methods=['POST'])
def decode_csr():
    try:
        # Get CSR input - either as file or text
        csr_file = request.files.get('csr_file')
        csr_text = request.form.get('csr_text', '')
        
        # Read CSR data
        if csr_file:
            csr_data = csr_file.read()
        elif csr_text:
            csr_data = csr_text.encode('utf-8')
        else:
            return jsonify({'error': 'CSR file or text is required'}), 400
        
        # Parse CSR
        try:
            csr = x509.load_pem_x509_csr(csr_data, default_backend())
        except Exception as e:
            return jsonify({'error': f'Invalid CSR format: {str(e)}'}), 400
        
        # Extract subject information in structured format
        subject_info = {
            'commonName': None,
            'organization': None,
            'organizationalUnitName': None,
            'countryName': None,
            'stateOrProvinceName': None,
            'localityName': None,
            'emailAddress': None
        }
        
        for attribute in csr.subject:
            oid_name = attribute.oid._name
            if oid_name in subject_info:
                subject_info[oid_name] = attribute.value
        
        # Extract public key information
        public_key = csr.public_key()
        key_type = type(public_key).__name__
        
        key_info = {
            'type': key_type,
            'size': None
        }
        
        if hasattr(public_key, 'key_size'):
            key_info['size'] = public_key.key_size
        
        # Extract extensions with special handling for Extended Key Usage
        extensions_info = []
        extended_key_usage = None
        
        for extension in csr.extensions:
            ext_name = extension.oid._name
            ext_critical = extension.critical
            ext_value = str(extension.value)
            
            # Try to format specific extension types nicely
            if isinstance(extension.value, x509.KeyUsage):
                usage_list = []
                if extension.value.digital_signature: usage_list.append('Digital Signature')
                if extension.value.key_encipherment: usage_list.append('Key Encipherment')
                if extension.value.content_commitment: usage_list.append('Content Commitment')
                if extension.value.data_encipherment: usage_list.append('Data Encipherment')
                if extension.value.key_agreement: usage_list.append('Key Agreement')
                if extension.value.key_cert_sign: usage_list.append('Key Cert Sign')
                if extension.value.crl_sign: usage_list.append('CRL Sign')
                ext_value = ', '.join(usage_list)
            elif isinstance(extension.value, x509.ExtendedKeyUsage):
                eku_list = []
                eku_display_list = []
                eku_name_map = {
                    'serverAuth': 'Server Authentication',
                    'clientAuth': 'Client Authentication',
                    'codeSigning': 'Code Signing',
                    'emailProtection': 'Email Protection',
                    'timeStamping': 'Time Stamping',
                    'ocspSigning': 'OCSP Signing'
                }
                for oid in extension.value:
                    oid_name = oid._name
                    eku_list.append(oid_name)
                    display_name = eku_name_map.get(oid_name, oid_name)
                    eku_display_list.append(display_name)
                ext_value = ', '.join(eku_display_list)
                extended_key_usage = ext_value  # Store for separate display
            elif isinstance(extension.value, x509.SubjectAlternativeName):
                san_list = []
                for name in extension.value:
                    san_list.append(str(name.value))
                ext_value = ', '.join(san_list)
            
            extensions_info.append({
                'name': ext_name,
                'critical': ext_critical,
                'value': ext_value
            })
        
        # Get signature algorithm
        signature_algorithm = csr.signature_algorithm_oid._name
        
        # Return decoded information as JSON
        return jsonify({
            'subject': subject_info,
            'public_key': key_info,
            'extensions': extensions_info,
            'signature_algorithm': signature_algorithm,
            'extended_key_usage': extended_key_usage
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/list-certificates', methods=['POST'])
@login_required
def list_certificates():
    """List all certificates from Azure Blob Storage with expiration dates"""
    try:
        from azure.storage.blob import BlobServiceClient
        from azure.core.credentials import AccessToken
        import datetime
        
        if not AZURE_BLOB_STORAGE_URL or not AZURE_BLOB_STORAGE_CONTAINER:
            return jsonify({'error': 'Azure Blob Storage is not configured'}), 400
        
        # Get a token specifically for Azure Storage
        storage_scope = ["https://storage.azure.com/.default"]
        storage_token = _get_token_from_cache(storage_scope)
        
        if not storage_token or "access_token" not in storage_token:
            # Token not in cache, acquire it silently
            cache = _load_cache()
            cca = _build_msal_app(cache=cache)
            accounts = cca.get_accounts()
            if accounts:
                storage_token = cca.acquire_token_silent(storage_scope, account=accounts[0])
                _save_cache(cache)
        
        if not storage_token or "access_token" not in storage_token:
            return jsonify({'error': 'Failed to acquire storage token. Please log out and log in again.'}), 401
        
        # Create a custom credential for blob storage
        class StorageCredential:
            def __init__(self, access_token):
                self.token = access_token
            
            def get_token(self, *scopes, **kwargs):
                return AccessToken(self.token, int(datetime.datetime.now().timestamp()) + 3600)
        
        storage_credential = StorageCredential(storage_token["access_token"])
        
        # Create blob service client
        blob_service_client = BlobServiceClient(
            account_url=AZURE_BLOB_STORAGE_URL,
            credential=storage_credential
        )
        
        # Get container client
        container_client = blob_service_client.get_container_client(AZURE_BLOB_STORAGE_CONTAINER)
        
        # Get filter parameter (optional)
        filter_ca = request.json.get('ca_filter') if request.is_json else None
        
        # List all blobs and collect CA directories
        certificates = []
        ca_directories = set()
        
        for blob in container_client.list_blobs():
            # Only process .crt and .pem files
            if blob.name.endswith(('.crt', '.pem')):
                # Extract CA directory from blob path (format: CA-name/filename.crt)
                ca_name = None
                if '/' in blob.name:
                    ca_name = blob.name.split('/')[0]
                    ca_directories.add(ca_name)
                
                # Apply filter if specified
                if filter_ca and ca_name != filter_ca:
                    continue
                
                try:
                    # Download blob content
                    blob_client = container_client.get_blob_client(blob.name)
                    cert_data = blob_client.download_blob().readall()
                    
                    # Parse certificate
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    
                    # Extract common name
                    cn = None
                    for attr in cert.subject:
                        if attr.oid == NameOID.COMMON_NAME:
                            cn = attr.value
                            break
                    
                    # Extract issuer common name
                    issuer_cn = None
                    for attr in cert.issuer:
                        if attr.oid == NameOID.COMMON_NAME:
                            issuer_cn = attr.value
                            break
                    
                    certificates.append({
                        'name': blob.name,
                        'ca_directory': ca_name or 'root',
                        'common_name': cn or 'Unknown',
                        'issuer': issuer_cn or 'Unknown',
                        'not_before': cert.not_valid_before.isoformat() if hasattr(cert, 'not_valid_before') else cert.not_valid_before_utc.isoformat(),
                        'not_after': cert.not_valid_after.isoformat() if hasattr(cert, 'not_valid_after') else cert.not_valid_after_utc.isoformat(),
                        'size': blob.size,
                        'last_modified': blob.last_modified.isoformat() if blob.last_modified else None,
                        'url': f"{AZURE_BLOB_STORAGE_URL}/{AZURE_BLOB_STORAGE_CONTAINER}/{blob.name}"
                    })
                except Exception as e:
                    # Skip files that can't be parsed as certificates
                    print(f"Warning: Failed to parse {blob.name}: {str(e)}")
                    continue
        
        # Sort by expiration date ascending (expiring first on top)
        certificates.sort(key=lambda x: x['not_after'], reverse=False)
        
        return jsonify({
            'certificates': certificates,
            'ca_directories': sorted(list(ca_directories))
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/convert-pfx-to-pem', methods=['POST'])
def convert_pfx_to_pem():
    try:
        # Get uploaded PFX file
        pfx_file = request.files.get('pfx_file')
        password = request.form.get('password', '')
        
        if not pfx_file:
            return jsonify({'error': 'PFX file is required'}), 400
        
        # Read PFX file
        pfx_data = pfx_file.read()
        
        # Load PFX
        try:
            from cryptography.hazmat.primitives.serialization import pkcs12
            
            pfx_password = password.encode('utf-8') if password else None
            
            private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                pfx_data,
                pfx_password,
                backend=default_backend()
            )
        except Exception as e:
            return jsonify({'error': f'Failed to load PFX file. Check password: {str(e)}'}), 400
        
        # Serialize private key to PEM
        private_key_pem = ''
        if private_key:
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
        
        # Serialize certificate to PEM
        certificate_pem = ''
        if certificate:
            certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Serialize chain certificates to PEM
        chain_pem = ''
        if additional_certs:
            for cert in additional_certs:
                chain_pem += cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Return results as JSON to display on page
        return jsonify({
            'private_key': private_key_pem,
            'certificate': certificate_pem,
            'chain': chain_pem
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sign-csr', methods=['POST'])
def sign_csr():
    try:
        # Get uploaded CSR file
        csr_file = request.files.get('csr')
        ca_cert_file = request.files.get('ca_cert')
        ca_key_file = request.files.get('ca_key')
        ca_key_password = request.form.get('ca_key_password', '')
        validity_days = int(request.form.get('validity_days', 365))
        
        if not csr_file:
            return jsonify({'error': 'CSR file is required'}), 400
        
        # Read CSR
        try:
            csr_data = csr_file.read()
            csr = x509.load_pem_x509_csr(csr_data, default_backend())
        except Exception as e:
            return jsonify({'error': f'Invalid CSR file: {str(e)}'}), 400
        
        # If CA cert and key provided, sign with them; otherwise create self-signed
        if ca_cert_file and ca_key_file:
            # Load CA certificate
            try:
                ca_cert_data = ca_cert_file.read()
                ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
            except Exception as e:
                return jsonify({'error': f'Invalid CA certificate: {str(e)}'}), 400
            
            # Load CA private key
            try:
                ca_key_data = ca_key_file.read()
                ca_key_pwd = ca_key_password.encode('utf-8') if ca_key_password else None
                ca_private_key = serialization.load_pem_private_key(
                    ca_key_data,
                    password=ca_key_pwd,
                    backend=default_backend()
                )
            except Exception as e:
                return jsonify({'error': f'Invalid CA private key: {str(e)}'}), 400
            
            issuer = ca_cert.subject
            signing_key = ca_private_key
        else:
            # Self-signed: use CSR's public key to generate a private key (simulation)
            # In reality, for self-signed, we need the original private key
            # For demo purposes, generate a new key pair
            signing_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            issuer = csr.subject
        
        # Build certificate
        import datetime
        
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(csr.subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(csr.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        cert_builder = cert_builder.not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=validity_days)
        )
        
        # Copy extensions from CSR
        for extension in csr.extensions:
            cert_builder = cert_builder.add_extension(
                extension.value,
                critical=extension.critical
            )
        
        # Add basic constraints for end-entity certificate
        try:
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
        except ValueError:
            # Extension might already exist from CSR
            pass
        
        # Sign the certificate
        certificate = cert_builder.sign(
            private_key=signing_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        # Serialize certificate to PEM
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Return the certificate
        from flask import send_file
        import io
        
        return send_file(
            io.BytesIO(cert_pem.encode('utf-8')),
            mimetype='application/x-pem-file',
            as_attachment=True,
            download_name='certificate.crt'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/convert-to-pfx', methods=['POST'])
def convert_to_pfx():
    try:
        # Get private key - either from file or text
        private_key_file = request.files.get('private_key')
        private_key_text = request.form.get('private_key_text', '')
        key_password = request.form.get('key_password', '')
        
        if private_key_file:
            private_key_data = private_key_file.read()
        elif private_key_text:
            private_key_data = private_key_text.encode('utf-8')
        else:
            return jsonify({'error': 'Private key (file or text) is required'}), 400
        
        # Get certificate - either from file or text
        certificate_file = request.files.get('certificate')
        certificate_text = request.form.get('certificate_text', '')
        
        if certificate_file:
            certificate_data = certificate_file.read()
        elif certificate_text:
            certificate_data = certificate_text.encode('utf-8')
        else:
            return jsonify({'error': 'Certificate (file or text) is required'}), 400
        
        # Get chain - either from file or text (optional)
        chain_file = request.files.get('chain')
        chain_text = request.form.get('chain_text', '')
        chain_data = None
        
        if chain_file:
            chain_data = chain_file.read()
        elif chain_text:
            chain_data = chain_text.encode('utf-8')
        
        # PFX password
        password = request.form.get('password', '')
        
        # Load the private key (with optional password)
        try:
            key_pwd = key_password.encode('utf-8') if key_password else None
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=key_pwd,
                backend=default_backend()
            )
        except Exception as e:
            return jsonify({'error': f'Invalid private key or wrong password: {str(e)}'}), 400
        
        # Load the certificate
        try:
            certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())
        except Exception as e:
            return jsonify({'error': f'Invalid certificate: {str(e)}'}), 400
        
        # Load chain certificates if provided
        chain_certs = None
        if chain_data:
            try:
                # Try to load multiple certificates from the chain data
                chain_certs = []
                # Split on BEGIN CERTIFICATE to handle multiple certs in one file
                import re
                cert_pattern = rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
                cert_matches = re.findall(cert_pattern, chain_data, re.DOTALL)
                
                for cert_data in cert_matches:
                    chain_certs.append(x509.load_pem_x509_certificate(cert_data, default_backend()))
                
                if not chain_certs:
                    # Try as single certificate
                    chain_certs = [x509.load_pem_x509_certificate(chain_data, default_backend())]
            except Exception as e:
                return jsonify({'error': f'Invalid chain certificate: {str(e)}'}), 400
        
        # Create PFX (PKCS12)
        pfx_password = password.encode('utf-8') if password else b''
        
        from cryptography.hazmat.primitives.serialization import pkcs12
        
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=b'certificate',
            key=private_key,
            cert=certificate,
            cas=chain_certs,
            encryption_algorithm=serialization.BestAvailableEncryption(pfx_password) if password else serialization.NoEncryption()
        )
        
        # Return the PFX file as a download
        from flask import send_file
        import io
        
        return send_file(
            io.BytesIO(pfx_data),
            mimetype='application/x-pkcs12',
            as_attachment=True,
            download_name='certificate.pfx'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/list-akv-certificates', methods=['POST'])
@login_required
def list_akv_certificates():
    """List certificates from Azure Key Vault"""
    try:
        from azure.identity import ClientSecretCredential
        from azure.core.credentials import AccessToken
        from azure.keyvault.certificates import CertificateClient
        import datetime
        
        # Get user's access token from session
        token = _get_token_from_cache(SCOPE)
        if not token or "access_token" not in token:
            return jsonify({'error': 'Azure authentication expired. Please log in again.'}), 401
        
        # Create a custom credential using the user's token
        class UserCredential:
            def __init__(self, access_token):
                self.token = access_token
            
            def get_token(self, *scopes, **kwargs):
                # Return the token with a far future expiration
                return AccessToken(self.token, int(datetime.datetime.now().timestamp()) + 3600)
        
        credential = UserCredential(token["access_token"])
        
        # Get vault URL from request
        vault_url = request.json.get('vault_url', '').strip()
        
        if not vault_url:
            return jsonify({'error': 'Key Vault URL is required'}), 400
        
        # List certificates from Key Vault
        try:
            cert_client = CertificateClient(vault_url=vault_url, credential=credential)
            certificates = []
            
            for cert_properties in cert_client.list_properties_of_certificates():
                certificates.append({
                    'name': cert_properties.name,
                    'enabled': cert_properties.enabled
                })
            
            return jsonify({'certificates': certificates})
            
        except Exception as e:
            return jsonify({'error': f'Failed to list certificates from Key Vault: {str(e)}'}), 400
        
    except ImportError as e:
        return jsonify({'error': f'Azure SDK not installed: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sign-csr-akv', methods=['POST'])
@login_required
def sign_csr_akv():
    try:
        from azure.identity import ClientSecretCredential
        from azure.core.credentials import AccessToken
        from azure.keyvault.certificates import CertificateClient
        from azure.keyvault.secrets import SecretClient
        import datetime
        
        # Get user's access token from session
        token = _get_token_from_cache(SCOPE)
        if not token or "access_token" not in token:
            return jsonify({'error': 'Azure authentication expired. Please log in again.'}), 401
        
        # Create a custom credential using the user's token
        class UserCredential:
            def __init__(self, access_token):
                self.token = access_token
            
            def get_token(self, *scopes, **kwargs):
                # Return the token with a far future expiration
                return AccessToken(self.token, int(datetime.datetime.now().timestamp()) + 3600)
        
        credential = UserCredential(token["access_token"])
        
        # Get CSR input - either as file or text
        csr_file = request.files.get('csr_file')
        csr_text = request.form.get('csr_text', '')
        
        # Read CSR data
        if csr_file:
            csr_data = csr_file.read()
        elif csr_text:
            csr_data = csr_text.encode('utf-8')
        else:
            return jsonify({'error': 'CSR file or text is required'}), 400
        
        # Parse CSR
        try:
            csr = x509.load_pem_x509_csr(csr_data, default_backend())
        except Exception as e:
            return jsonify({'error': f'Invalid CSR format: {str(e)}'}), 400
        
        # Get Azure Key Vault parameters
        vault_url = request.form.get('vault_url', '').strip()
        certificate_name = request.form.get('certificate_name', '').strip()
        validity_days = int(request.form.get('validity_days', 365))
        
        if not vault_url:
            return jsonify({'error': 'Key Vault URL is required'}), 400
        if not certificate_name:
            return jsonify({'error': 'Certificate name is required'}), 400
        
        # Get CA certificate from Key Vault
        try:
            cert_client = CertificateClient(vault_url=vault_url, credential=credential)
            certificate = cert_client.get_certificate(certificate_name)
            
            # Get the certificate in PEM format
            ca_cert = x509.load_der_x509_certificate(certificate.cer, default_backend())
        except Exception as e:
            return jsonify({'error': f'Failed to retrieve certificate from Key Vault: {str(e)}'}), 400
        
        # Get the private key from Key Vault (stored as secret)
        try:
            secret_client = SecretClient(vault_url=vault_url, credential=credential)
            
            # The private key is stored as a secret with the same name
            secret = secret_client.get_secret(certificate_name)
            
            # Parse the secret value which contains the private key
            # Key Vault stores it as PFX, we need to extract the private key
            from cryptography.hazmat.primitives.serialization import pkcs12
            
            # The secret value is base64-encoded PFX
            import base64
            pfx_data = base64.b64decode(secret.value)
            
            # Load PFX (no password for Key Vault certificates)
            private_key, cert_from_pfx, additional_certs = pkcs12.load_key_and_certificates(
                pfx_data,
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            return jsonify({'error': f'Failed to retrieve private key from Key Vault: {str(e)}. Make sure the certificate has an exportable private key.'}), 400
        
        # Build CA chain (including the CA cert itself)
        ca_chain_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Add any additional certificates from the chain
        if additional_certs:
            for chain_cert in additional_certs:
                ca_chain_pem += chain_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Build and sign certificate
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(csr.subject)
        cert_builder = cert_builder.issuer_name(ca_cert.subject)
        cert_builder = cert_builder.public_key(csr.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        cert_builder = cert_builder.not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=validity_days)
        )
        
        # Copy extensions from CSR
        for extension in csr.extensions:
            try:
                cert_builder = cert_builder.add_extension(
                    extension.value,
                    critical=extension.critical
                )
            except ValueError:
                # Skip if extension already exists
                pass
        
        # Add basic constraints for end-entity certificate
        try:
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
        except ValueError:
            # Extension might already exist from CSR
            pass
        
        # Sign the certificate
        signed_certificate = cert_builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        # Serialize certificate to PEM
        cert_pem = signed_certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Upload certificate to Azure Blob Storage
        blob_url = None
        if AZURE_BLOB_STORAGE_URL and AZURE_BLOB_STORAGE_CONTAINER:
            try:
                from azure.storage.blob import BlobServiceClient
                
                # Get a token specifically for Azure Storage
                storage_scope = ["https://storage.azure.com/.default"]
                storage_token = _get_token_from_cache(storage_scope)
                
                if not storage_token or "access_token" not in storage_token:
                    # Token not in cache, acquire it silently
                    cache = _load_cache()
                    cca = _build_msal_app(cache=cache)
                    accounts = cca.get_accounts()
                    if accounts:
                        storage_token = cca.acquire_token_silent(storage_scope, account=accounts[0])
                        _save_cache(cache)
                
                if storage_token and "access_token" in storage_token:
                    # Create a custom credential for blob storage
                    class StorageCredential:
                        def __init__(self, access_token):
                            self.token = access_token
                        
                        def get_token(self, *scopes, **kwargs):
                            return AccessToken(self.token, int(datetime.datetime.now().timestamp()) + 3600)
                    
                    storage_credential = StorageCredential(storage_token["access_token"])
                    
                    # Create blob service client using storage credential
                    blob_service_client = BlobServiceClient(
                        account_url=AZURE_BLOB_STORAGE_URL,
                        credential=storage_credential
                    )
                else:
                    raise Exception("Failed to acquire storage token")
                
                # Get container client
                container_client = blob_service_client.get_container_client(AZURE_BLOB_STORAGE_CONTAINER)
                
                # Generate blob name: CA-name/CN-timestamp.crt
                # Extract CN from the certificate
                cn = None
                for attr in signed_certificate.subject:
                    if attr.oid == NameOID.COMMON_NAME:
                        cn = attr.value
                        break
                
                # Create a safe filename from CN
                import re
                safe_cn = re.sub(r'[^\w\-\.]', '_', cn) if cn else 'certificate'
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                blob_name = f"{certificate_name}/{safe_cn}_{timestamp}.crt"
                
                # Upload the certificate
                blob_client = container_client.get_blob_client(blob_name)
                blob_client.upload_blob(cert_pem, overwrite=True)
                
                # Generate the blob URL
                blob_url = f"{AZURE_BLOB_STORAGE_URL}/{AZURE_BLOB_STORAGE_CONTAINER}/{blob_name}"
                
            except Exception as e:
                # Don't fail the request if blob upload fails, just log it
                print(f"Warning: Failed to upload certificate to blob storage: {str(e)}")
        
        # Return the certificate and CA chain as JSON
        response_data = {
            'certificate': cert_pem,
            'ca_chain': ca_chain_pem
        }
        
        if blob_url:
            response_data['blob_url'] = blob_url
        
        return jsonify(response_data)
        
    except ImportError as e:
        return jsonify({'error': f'Azure SDK not installed: {str(e)}. Please install: pip install azure-identity azure-keyvault-certificates azure-keyvault-secrets'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Startup checks
    if CLIENT_ID and not EXTERNAL_URL:
        print("⚠️  WARNING: Azure authentication is configured but EXTERNAL_URL is not set.")
        print("⚠️  OAuth callbacks may fail when behind a reverse proxy.")
        print("⚠️  Set EXTERNAL_URL in your .env file to your public HTTPS domain.")
        print("⚠️  Example: EXTERNAL_URL=https://certificate-tools.soep.org")
        print()
    
    if EXTERNAL_URL:
        print(f"✓ Using external URL for OAuth callbacks: {EXTERNAL_URL}")
        print(f"✓ OAuth redirect URI will be: {EXTERNAL_URL}{REDIRECT_PATH}")
        print()
    
    app.run(debug=True, host='0.0.0.0', port=5001)
