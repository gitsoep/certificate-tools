"""
Azure-related routes (Key Vault, Blob Storage)
"""
import io
import re
import base64
import logging
import datetime
import urllib.parse
from flask import Blueprint, render_template, request, jsonify, session, current_app, send_file, url_for
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

from ..utils.decorators import login_required
from ..utils.credentials import UserCredential, StorageCredential
from ..services.auth import AuthService
from ..services.certificate import CertificateService

bp = Blueprint('azure', __name__)
logger = logging.getLogger(__name__)


def _normalize_and_validate_vault_url(vault_url: str) -> str:
    """
    Parse and validate a Key Vault URL, returning a normalized, safe URL.

    Enforces HTTPS scheme and restricts the hostname to known-good Key Vault domains.
    Raises ValueError if the URL is invalid or not allowed.
    """
    if not vault_url:
        raise ValueError("Empty Key Vault URL")

    parsed = urllib.parse.urlparse(vault_url.strip())

    # Require an explicit scheme and netloc.
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Key Vault URL must include scheme and host")

    if parsed.scheme.lower() != "https":
        raise ValueError("Key Vault URL must use HTTPS")

    hostname = parsed.hostname or ""

    # Basic allowlist: restrict to Azure Key Vault public endpoints.
    # Adjust or extend this as needed for your deployment.
    allowed_suffixes = (".vault.azure.net",)
    if not any(hostname.endswith(suffix) for suffix in allowed_suffixes):
        raise ValueError("Key Vault host is not allowed")

    # Reject embedded credentials in the URL for safety.
    if parsed.username or parsed.password:
        raise ValueError("Key Vault URL must not contain credentials")

    # Normalize: keep scheme, host (and port if present); drop query/fragment.
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

   # Use root path for Key Vault operations.
    normalized = urllib.parse.urlunparse(
        ("https", netloc, "/", "", "", "")
    )
    return normalized


def _validate_vault_url(vault_url: str) -> bool:
    """
    Backwards-compatible boolean validator that uses the normalized validator
    under the hood.
    """
    try:
        _normalize_and_validate_vault_url(vault_url)
        return True
    except Exception:
        return False

# Regex for valid Azure Key Vault URLs (including sovereign clouds)
_VAULT_URL_PATTERN = re.compile(
    r'^https://[a-zA-Z0-9-]+\.vault\.(azure\.net|azure\.cn|usgovcloudapi\.net|microsoftazure\.de)/?$'
)


def _validate_vault_url(vault_url):
    """Validate that a vault URL matches the Azure Key Vault format and is in the configured allowlist."""
    if not _VAULT_URL_PATTERN.match(vault_url):
        return False
    allowed = current_app.config.get('AZURE_KEYVAULT_URLS', [])
    return vault_url.rstrip('/') in [u.rstrip('/') for u in allowed]


@bp.route('/csr-signer-akv')
@login_required
def csr_signer_akv():
    """Azure Key Vault CSR signer page."""
    user = session.get("user")
    vault_urls = current_app.config.get('AZURE_KEYVAULT_URLS', [])
    return render_template('csr_signer_akv.html',
                         active_page='csr-signer-akv',
                         user=user,
                         vault_urls=vault_urls,
                         app_title=current_app.config['APP_TITLE'])


@bp.route('/pki-mtls')
@login_required
def pki():
    """PKI mTLS page."""
    user = session.get("user")
    vault_urls = current_app.config.get('AZURE_KEYVAULT_URLS', [])
    return render_template('pki_mtls.html',
                         active_page='pki-mtls',
                         user=user,
                         vault_urls=vault_urls,
                         app_title=current_app.config['APP_TITLE'])


@bp.route('/certificate-list')
@login_required
def certificate_list():
    """Certificate list page."""
    user = session.get("user")
    return render_template('certificate_list.html',
                         active_page='certificate-list',
                         user=user,
                         app_title=current_app.config['APP_TITLE'])


@bp.route('/list-certificates', methods=['POST'])
@login_required
def list_certificates():
    """List all certificates from Azure Blob Storage with expiration dates."""
    try:
        from azure.storage.blob import BlobServiceClient
        
        blob_url = current_app.config.get('AZURE_BLOB_STORAGE_URL')
        container = current_app.config.get('AZURE_BLOB_STORAGE_CONTAINER')
        external_url = current_app.config.get('EXTERNAL_URL')
        
        if not blob_url or not container:
            return jsonify({'error': 'Azure Blob Storage is not configured'}), 400
        
        # Get storage token
        storage_scope = ["https://storage.azure.com/.default"]
        storage_token = AuthService.get_token_from_cache(storage_scope)
        
        if not storage_token or "access_token" not in storage_token:
            cache = AuthService.load_cache()
            cca = AuthService.build_msal_app(cache=cache)
            accounts = cca.get_accounts()
            if accounts:
                storage_token = cca.acquire_token_silent(storage_scope, account=accounts[0])
                AuthService.save_cache(cache)
        
        if not storage_token or "access_token" not in storage_token:
            return jsonify({'error': 'Failed to acquire storage token. Please log in again.'}), 401
        
        storage_credential = StorageCredential(storage_token["access_token"])
        blob_service_client = BlobServiceClient(account_url=blob_url, credential=storage_credential)
        container_client = blob_service_client.get_container_client(container)
        
        filter_ca = request.json.get('ca_filter') if request.is_json else None
        
        certificates = []
        ca_directories = set()
        
        for blob in container_client.list_blobs():
            if blob.name.endswith(('.crt', '.pem')):
                ca_name = None
                if '/' in blob.name:
                    ca_name = blob.name.split('/')[0]
                    ca_directories.add(ca_name)
                
                if filter_ca and ca_name != filter_ca:
                    continue
                
                try:
                    blob_client = container_client.get_blob_client(blob.name)
                    cert_data = blob_client.download_blob().readall()
                    cert = CertificateService.load_certificate(cert_data)
                    
                    cn = None
                    for attr in cert.subject:
                        if attr.oid == NameOID.COMMON_NAME:
                            cn = attr.value
                            break
                    
                    issuer_cn = None
                    for attr in cert.issuer:
                        if attr.oid == NameOID.COMMON_NAME:
                            issuer_cn = attr.value
                            break
                    
                    email_addr = None
                    try:
                        for attr in cert.subject:
                            if attr.oid == NameOID.EMAIL_ADDRESS:
                                email_addr = attr.value
                                break
                        if not email_addr:
                            try:
                                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                                rfc_emails = san.get_values_for_type(x509.RFC822Name)
                                if rfc_emails:
                                    email_addr = rfc_emails[0]
                            except Exception:
                                pass
                    except Exception:
                        pass
                    
                    if external_url:
                        download_url = f"{external_url}/download?blob=" + urllib.parse.quote(blob.name)
                    else:
                        download_url = f"/download?blob=" + urllib.parse.quote(blob.name)
                    
                    certificates.append({
                        'name': blob.name,
                        'ca_directory': ca_name or 'root',
                        'common_name': cn or 'Unknown',
                        'issuer': issuer_cn or 'Unknown',
                        'email': email_addr,
                        'not_before': cert.not_valid_before_utc.isoformat(),
                        'not_after': cert.not_valid_after_utc.isoformat(),
                        'size': blob.size,
                        'last_modified': blob.last_modified.isoformat() if blob.last_modified else None,
                        'url': download_url
                    })
                except Exception as e:
                    logger.warning(f"Failed to parse {blob.name}: {str(e)}")
                    continue
        
        certificates.sort(key=lambda x: x['not_after'], reverse=False)
        
        return jsonify({
            'certificates': certificates,
            'ca_directories': sorted(list(ca_directories))
        })
    
    except Exception as e:
        logger.error(f'Error listing certificates: {str(e)}')
        return jsonify({'error': 'An error occurred while listing certificates.'}), 500


@bp.route('/download')
@login_required
def download():
    """Download a certificate blob via proxy endpoint."""
    try:
        from azure.storage.blob import BlobServiceClient
        
        blob_path = request.args.get('blob') or request.args.get('name')
        if not blob_path:
            return jsonify({'error': 'Missing blob parameter'}), 400
        
        blob_url = current_app.config.get('AZURE_BLOB_STORAGE_URL')
        container = current_app.config.get('AZURE_BLOB_STORAGE_CONTAINER')
        
        if not blob_url or not container:
            return jsonify({'error': 'Azure Blob Storage is not configured'}), 400
        
        storage_scope = ["https://storage.azure.com/.default"]
        storage_token = AuthService.get_token_from_cache(storage_scope)
        
        if not storage_token or "access_token" not in storage_token:
            cache = AuthService.load_cache()
            cca = AuthService.build_msal_app(cache=cache)
            accounts = cca.get_accounts()
            if accounts:
                storage_token = cca.acquire_token_silent(storage_scope, account=accounts[0])
                AuthService.save_cache(cache)
        
        if not storage_token or "access_token" not in storage_token:
            return jsonify({'error': 'Failed to acquire storage token.'}), 401
        
        storage_credential = StorageCredential(storage_token["access_token"])
        blob_service_client = BlobServiceClient(account_url=blob_url, credential=storage_credential)
        container_client = blob_service_client.get_container_client(container)
        blob_client = container_client.get_blob_client(blob_path)
        
        data = blob_client.download_blob().readall()
        
        import os
        basename = os.path.basename(blob_path)
        mimetype = 'application/octet-stream'
        if basename.endswith('.pem'):
            mimetype = 'application/x-pem-file'
        elif basename.endswith('.crt'):
            mimetype = 'application/x-x509-ca-cert'
        
        return send_file(
            io.BytesIO(data),
            mimetype=mimetype,
            as_attachment=True,
            download_name=basename
        )
    
    except Exception as e:
        logger.error(f'Download error: {str(e)}')
        return jsonify({'error': 'Failed to download the certificate.'}), 500


@bp.route('/list-akv-certificates', methods=['POST'])
@login_required
def list_akv_certificates():
    """List certificates from Azure Key Vault(s)."""
    try:
        from azure.keyvault.certificates import CertificateClient
        
        scope = current_app.config.get('AZURE_SCOPE')
        token = AuthService.get_token_from_cache(scope)
        
        if not token or "access_token" not in token:
            return jsonify({'error': 'Azure authentication expired. Please log in again.'}), 401
        
        credential = UserCredential(token["access_token"])
        
        configured_vault_urls = current_app.config.get('AZURE_KEYVAULT_URLS', []) or []
        request_vault_ids = request.json.get('vault_urls', []) if request.is_json else []
        
        # Build a mapping from a stable identifier (vault name) to the configured vault URL.
        configured_vault_map = {}
        for cfg_url in configured_vault_urls:
            cfg_url_str = str(cfg_url)
            # Derive vault identifier from URL host portion, e.g., https://{vault_name}.vault.azure.net/...
            try:
                parsed = urllib.parse.urlparse(cfg_url_str)
                host = parsed.hostname or ''
                vault_id = host.split('.')[0] if host else cfg_url_str
            except Exception:
                vault_id = cfg_url_str
            if vault_id and vault_id not in configured_vault_map:
                configured_vault_map[vault_id] = cfg_url_str
        
        # Only allow user to select from configured vaults by identifier; do not allow arbitrary URLs.
        if request_vault_ids:
            filtered_vault_urls = []
            disallowed_vault_ids = []
            for requested_id in request_vault_ids:
                requested_id_str = str(requested_id)
                cfg_url = configured_vault_map.get(requested_id_str)
                if cfg_url is not None:
                    filtered_vault_urls.append(cfg_url)
                else:
                    disallowed_vault_ids.append(requested_id_str)
            vault_urls = filtered_vault_urls
        else:
            vault_urls = [str(u) for u in configured_vault_urls]
        
        if not vault_urls:
            return jsonify({'error': 'No valid Key Vault URLs configured or provided'}), 400
        
        all_certificates = []
        vault_errors = []
        
        # Report any user-provided vault identifiers that were not in the configured allowlist.
        if request_vault_ids:
            for invalid_id in disallowed_vault_ids:
                vault_errors.append({'vault_url': invalid_id, 'error': 'Vault identifier not in allowlist'})
        
        for vault_url in vault_urls:
            if not _validate_vault_url(vault_url):
                vault_errors.append({'vault_url': vault_url, 'error': 'Vault URL not in allowlist or invalid format'})
                continue
            try:
                cert_client = CertificateClient(vault_url=vault_url, credential=credential)
                vault_name = vault_url.split('//')[1].split('.')[0] if '//' in vault_url else vault_url
                
                for cert_props in cert_client.list_properties_of_certificates():
                    all_certificates.append({
                        'name': cert_props.name,
                        'enabled': cert_props.enabled,
                        'vault_url': vault_url,
                        'vault_name': vault_name
                    })
            except Exception as e:
                vault_errors.append({'vault_url': vault_url, 'error': str(e)})
        
        response = {'certificates': all_certificates}
        if vault_errors:
            response['vault_errors'] = vault_errors
        
        return jsonify(response)
    
    except ImportError:
        return jsonify({'error': 'Azure SDK is not installed.'}), 500
    except Exception as e:
        logger.error(f'Error listing Key Vault certificates: {str(e)}')
        return jsonify({'error': 'An error occurred while listing certificates.'}), 500


@bp.route('/sign-csr-akv', methods=['POST'])
@login_required
def sign_csr_akv():
    """Sign a CSR using Azure Key Vault."""
    try:
        from azure.keyvault.certificates import CertificateClient
        from azure.keyvault.secrets import SecretClient
        
        scope = current_app.config.get('AZURE_SCOPE')
        token = AuthService.get_token_from_cache(scope)
        
        if not token or "access_token" not in token:
            return jsonify({'error': 'Azure authentication expired. Please log in again.'}), 401
        
        credential = UserCredential(token["access_token"])
        
        # Get CSR input
        csr_file = request.files.get('csr_file')
        csr_text = request.form.get('csr_text', '')
        
        if csr_file:
            csr_data = csr_file.read()
        elif csr_text:
            csr_data = csr_text.encode('utf-8')
        else:
            return jsonify({'error': 'CSR file or text is required'}), 400
        
        try:
            csr = CertificateService.load_csr(csr_data)
        except Exception:
            return jsonify({'error': 'Invalid CSR format'}), 400
        
        vault_url = request.form.get('vault_url', '').strip()
        certificate_name = request.form.get('certificate_name', '').strip()
        validity_days = int(request.form.get('validity_days', 365))
        
        if not vault_url:
            return jsonify({'error': 'Key Vault URL is required'}), 400
        if not _validate_vault_url(vault_url):
            return jsonify({'error': 'Key Vault URL is not allowed or has an invalid format'}), 400
        if not certificate_name:
            return jsonify({'error': 'Certificate name is required'}), 400

        # Normalize and re-validate the Key Vault URL to prevent SSRF.
        try:
            safe_vault_url = _normalize_and_validate_vault_url(vault_url)
        except Exception:
            return jsonify({'error': 'Key Vault URL is not allowed or has an invalid format'}), 400
        
        # Get CA certificate from Key Vault
        try:
            cert_client = CertificateClient(vault_url=safe_vault_url, credential=credential)
            certificate = cert_client.get_certificate(certificate_name)
            ca_cert = CertificateService.load_der_certificate(certificate.cer)
        except Exception as e:
            logger.error(f'Failed to retrieve certificate from Key Vault: {str(e)}')
            return jsonify({'error': 'Failed to retrieve certificate from Key Vault.'}), 400
        
        # Get private key from Key Vault
        try:
            secret_client = SecretClient(vault_url=safe_vault_url, credential=credential)
            secret = secret_client.get_secret(certificate_name)
            pfx_data = base64.b64decode(secret.value)
            private_key, cert_from_pfx, additional_certs = pkcs12.load_key_and_certificates(
                pfx_data, password=None, backend=default_backend()
            )
        except Exception as e:
            logger.error(f'Failed to retrieve private key from Key Vault: {str(e)}')
            return jsonify({'error': 'Failed to retrieve private key from Key Vault.'}), 400
        
        # Build CA chain
        ca_chain_pem = CertificateService.serialize_certificate(ca_cert)
        if additional_certs:
            for chain_cert in additional_certs:
                ca_chain_pem += CertificateService.serialize_certificate(chain_cert)
        
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
        
        for extension in csr.extensions:
            try:
                cert_builder = cert_builder.add_extension(extension.value, critical=extension.critical)
            except ValueError:
                pass
        
        try:
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
        except ValueError:
            pass
        
        signed_certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())
        cert_pem = CertificateService.serialize_certificate(signed_certificate)
        
        # Upload to blob storage if requested
        upload_to_blob = request.form.get('upload_to_blob', 'false').lower() == 'true'
        blob_url = None
        
        blob_storage_url = current_app.config.get('AZURE_BLOB_STORAGE_URL')
        blob_container = current_app.config.get('AZURE_BLOB_STORAGE_CONTAINER')
        external_url = current_app.config.get('EXTERNAL_URL')
        
        if upload_to_blob and blob_storage_url and blob_container:
            try:
                from azure.storage.blob import BlobServiceClient
                
                storage_scope = ["https://storage.azure.com/.default"]
                storage_token = AuthService.get_token_from_cache(storage_scope)
                
                if not storage_token or "access_token" not in storage_token:
                    cache = AuthService.load_cache()
                    cca = AuthService.build_msal_app(cache=cache)
                    accounts = cca.get_accounts()
                    if accounts:
                        storage_token = cca.acquire_token_silent(storage_scope, account=accounts[0])
                        AuthService.save_cache(cache)
                
                if storage_token and "access_token" in storage_token:
                    storage_credential = StorageCredential(storage_token["access_token"])
                    blob_service_client = BlobServiceClient(
                        account_url=blob_storage_url, credential=storage_credential
                    )
                    container_client = blob_service_client.get_container_client(blob_container)
                    
                    cn = None
                    for attr in signed_certificate.subject:
                        if attr.oid == NameOID.COMMON_NAME:
                            cn = attr.value
                            break
                    
                    safe_cn = re.sub(r'[^\w\-\.]', '_', cn) if cn else 'certificate'
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    blob_name = f"{certificate_name}/{safe_cn}_{timestamp}.crt"
                    
                    blob_client = container_client.get_blob_client(blob_name)
                    blob_client.upload_blob(cert_pem, overwrite=True)
                    
                    if external_url:
                        blob_url = f"{external_url}/download?blob={urllib.parse.quote(blob_name)}"
                    else:
                        blob_url = url_for('azure.download', blob=blob_name, _external=True)
            except Exception as e:
                logger.warning(f"Failed to upload certificate to blob storage: {str(e)}")
        
        response_data = {'certificate': cert_pem, 'ca_chain': ca_chain_pem}
        if blob_url:
            response_data['blob_url'] = blob_url
        
        return jsonify(response_data)
    
    except ImportError:
        return jsonify({'error': 'Azure SDK is not installed.'}), 500
    except Exception as e:
        logger.error(f'Error signing CSR with Key Vault: {str(e)}')
        return jsonify({'error': 'An error occurred while signing the CSR.'}), 500
