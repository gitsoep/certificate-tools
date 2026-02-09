"""
Certificate format conversion routes (PEM <-> PFX)
"""
import io
import logging
from flask import Blueprint, render_template, request, jsonify, session, current_app, send_file
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from ..services.certificate import CertificateService

bp = Blueprint('converter', __name__)
logger = logging.getLogger(__name__)


@bp.route('/pfx-converter')
def pfx_converter():
    """PEM to PFX converter page."""
    user = session.get("user")
    return render_template('pfx_converter.html',
                         active_page='pfx-converter',
                         user=user,
                         app_title=current_app.config['APP_TITLE'])


@bp.route('/pfx-to-pem')
def pfx_to_pem():
    """PFX to PEM converter page."""
    user = session.get("user")
    return render_template('pfx_to_pem.html',
                         active_page='pfx-to-pem',
                         user=user,
                         app_title=current_app.config['APP_TITLE'])


@bp.route('/convert-to-pfx', methods=['POST'])
def convert_to_pfx():
    """Convert PEM files to PFX format."""
    try:
        # Get private key
        private_key_file = request.files.get('private_key')
        private_key_text = request.form.get('private_key_text', '')
        key_password = request.form.get('key_password', '')
        
        if private_key_file:
            private_key_data = private_key_file.read()
        elif private_key_text:
            private_key_data = private_key_text.encode('utf-8')
        else:
            return jsonify({'error': 'Private key is required'}), 400
        
        # Get certificate
        certificate_file = request.files.get('certificate')
        certificate_text = request.form.get('certificate_text', '')
        
        if certificate_file:
            certificate_data = certificate_file.read()
        elif certificate_text:
            certificate_data = certificate_text.encode('utf-8')
        else:
            return jsonify({'error': 'Certificate is required'}), 400
        
        # Get chain (optional)
        chain_file = request.files.get('chain')
        chain_text = request.form.get('chain_text', '')
        chain_data = None
        
        if chain_file:
            chain_data = chain_file.read()
        elif chain_text:
            chain_data = chain_text.encode('utf-8')
        
        password = request.form.get('password', '')
        
        # Load private key
        try:
            key_pwd = key_password.encode('utf-8') if key_password else None
            private_key = CertificateService.load_private_key(private_key_data, key_pwd)
        except Exception as e:
            logger.error(f'Invalid private key: {str(e)}')
            return jsonify({'error': 'Invalid private key format or password.'}), 400
        
        # Load certificate
        try:
            certificate = CertificateService.load_certificate(certificate_data)
        except Exception as e:
            logger.error(f'Invalid certificate: {str(e)}')
            return jsonify({'error': 'Invalid certificate format.'}), 400
        
        # Load chain certificates
        chain_certs = None
        if chain_data:
            try:
                chain_certs = []
                parts = chain_data.split(b'-----BEGIN CERTIFICATE-----')
                for part in parts[1:]:
                    if b'-----END CERTIFICATE-----' in part:
                        cert_pem = b'-----BEGIN CERTIFICATE-----' + part.split(b'-----END CERTIFICATE-----')[0] + b'-----END CERTIFICATE-----'
                        chain_certs.append(x509.load_pem_x509_certificate(cert_pem, default_backend()))
                if not chain_certs:
                    chain_certs = [x509.load_pem_x509_certificate(chain_data, default_backend())]
            except Exception as e:
                logger.error(f'Invalid chain certificate: {str(e)}')
                return jsonify({'error': 'Invalid chain certificate format.'}), 400
        
        # Create PFX
        pfx_password = password.encode('utf-8') if password else b''
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=b'certificate',
            key=private_key,
            cert=certificate,
            cas=chain_certs,
            encryption_algorithm=serialization.BestAvailableEncryption(pfx_password) if password else serialization.NoEncryption()
        )
        
        return send_file(
            io.BytesIO(pfx_data),
            mimetype='application/x-pkcs12',
            as_attachment=True,
            download_name='certificate.pfx'
        )
    
    except Exception as e:
        logger.error(f'Error converting to PFX: {str(e)}')
        return jsonify({'error': 'An error occurred while creating the PFX file.'}), 500


@bp.route('/convert-pfx-to-pem', methods=['POST'])
def convert_pfx_to_pem():
    """Convert PFX to PEM format."""
    try:
        pfx_file = request.files.get('pfx_file')
        password = request.form.get('password', '')
        
        if not pfx_file:
            return jsonify({'error': 'PFX file is required'}), 400
        
        pfx_data = pfx_file.read()
        
        try:
            pfx_password = password.encode('utf-8') if password else None
            private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                pfx_data, pfx_password, backend=default_backend()
            )
        except Exception as e:
            logger.error(f'Failed to load PFX file: {str(e)}')
            return jsonify({'error': 'Failed to load PFX file. Check format and password.'}), 400
        
        private_key_pem = ''
        if private_key:
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
        
        certificate_pem = ''
        if certificate:
            certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        chain_pem = ''
        if additional_certs:
            for cert in additional_certs:
                chain_pem += cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        return jsonify({
            'private_key': private_key_pem,
            'certificate': certificate_pem,
            'chain': chain_pem
        })
    
    except Exception as e:
        logger.error(f'Error converting PFX to PEM: {str(e)}')
        return jsonify({'error': 'An error occurred while converting the PFX file.'}), 500
