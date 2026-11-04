"""
CSR generation and signing routes
"""
import logging
from flask import Blueprint, render_template, request, jsonify, session, current_app
from ..services.certificate import CertificateService
from ..config import Config

bp = Blueprint('csr', __name__)
logger = logging.getLogger(__name__)


@bp.route('/csr-generator')
def csr_generator():
    """CSR generator page."""
    user = session.get("user")
    return render_template('csr_generator.html',
                         defaults=Config.get_csr_defaults(),
                         active_page='csr-generator',
                         user=user,
                         app_title=current_app.config['APP_TITLE'])


@bp.route('/generate', methods=['POST'])
def generate_csr():
    """Generate a CSR and private key."""
    try:
        defaults = Config.get_csr_defaults()
        
        # Get form data
        country = request.form.get('country', defaults['country'])
        state = request.form.get('state', defaults['state'])
        locality = request.form.get('locality', defaults['locality'])
        organization = request.form.get('organization', defaults['organization'])
        organizational_unit = request.form.get('organizational_unit', defaults['organizational_unit'])
        common_name = request.form.get('common_name', defaults['common_name'])
        email = request.form.get('email', defaults['email'])
        key_option = request.form.get('key_option', 'generate')
        eku_selection = request.form.get('eku', 'clientAuth')
        signature_algorithm = request.form.get('signature_algorithm', 'SHA256')
        
        if not common_name:
            return jsonify({'error': 'Common Name is required'}), 400
        
        # Handle private key
        if key_option == 'existing':
            key_input_method = request.form.get('key_input_method', 'paste')
            
            if key_input_method == 'paste':
                private_key_text = request.form.get('private_key_text', '').strip()
                if not private_key_text:
                    return jsonify({'error': 'Private key text is required'}), 400
                try:
                    private_key = CertificateService.load_private_key(private_key_text.encode('utf-8'))
                except Exception as e:
                    logger.error(f'Invalid private key text: {str(e)}')
                    return jsonify({'error': 'Invalid private key format.'}), 400
            else:
                private_key_file = request.files.get('private_key_file')
                if not private_key_file:
                    return jsonify({'error': 'Private key file is required'}), 400
                try:
                    private_key = CertificateService.load_private_key(private_key_file.read())
                except Exception as e:
                    logger.error(f'Invalid private key file: {str(e)}')
                    return jsonify({'error': 'Invalid private key file format.'}), 400
        else:
            ALLOWED_KEY_SIZES = {2048, 3072, 4096, 8192}
            key_size = int(request.form.get('key_size', defaults['key_size']))
            if key_size not in ALLOWED_KEY_SIZES:
                return jsonify({'error': f'Invalid key size. Allowed values: {sorted(ALLOWED_KEY_SIZES)}'}), 400
            private_key = CertificateService.generate_private_key(signature_algorithm, key_size)
        
        # Build subject name
        subject_name = CertificateService.build_subject_name(
            country=country, state=state, locality=locality,
            organization=organization, organizational_unit=organizational_unit,
            common_name=common_name, email=email
        )
        
        # Get hash algorithm and build CSR
        hash_algorithm = CertificateService.get_hash_algorithm(signature_algorithm)
        csr = CertificateService.build_csr(subject_name, private_key, eku_selection, hash_algorithm)
        csr_pem = CertificateService.serialize_csr(csr)
        
        show_private_key = (key_option != 'existing')
        
        if show_private_key:
            private_key_pem = CertificateService.serialize_private_key(private_key)
            return render_template('csr-generator-result.html',
                                 private_key=private_key_pem,
                                 csr=csr_pem,
                                 common_name=common_name,
                                 show_private_key=True,
                                 user=session.get("user"),
                                 app_title=current_app.config['APP_TITLE'])
        else:
            return render_template('csr-generator-result.html',
                                 csr=csr_pem,
                                 common_name=common_name,
                                 show_private_key=False,
                                 user=session.get("user"),
                                 app_title=current_app.config['APP_TITLE'])
    
    except Exception as e:
        logger.error(f'Error generating CSR: {str(e)}')
        return jsonify({'error': 'An error occurred while generating the CSR.'}), 500


@bp.route('/csr-signer')
def csr_signer():
    """CSR signer page."""
    user = session.get("user")
    return render_template('csr_signer.html',
                         active_page='csr-signer',
                         user=user,
                         app_title=current_app.config['APP_TITLE'])


@bp.route('/sign-csr', methods=['POST'])
def sign_csr():
    """Sign a CSR with a CA certificate."""
    try:
        from flask import send_file
        import io
        
        csr_file = request.files.get('csr')
        ca_cert_file = request.files.get('ca_cert')
        ca_key_file = request.files.get('ca_key')
        ca_key_password = request.form.get('ca_key_password', '')
        validity_days = int(request.form.get('validity_days', 365))
        if not 1 <= validity_days <= 3650:
            return jsonify({'error': 'validity_days must be between 1 and 3650'}), 400
        
        if not csr_file:
            return jsonify({'error': 'CSR file is required'}), 400
        
        try:
            csr = CertificateService.load_csr(csr_file.read())
        except Exception as e:
            logger.error(f'Invalid CSR file: {str(e)}')
            return jsonify({'error': 'Invalid CSR file format.'}), 400
        
        if not ca_cert_file or not ca_key_file:
            return jsonify({'error': 'CA certificate and CA private key are required'}), 400
        
        try:
            ca_cert = CertificateService.load_certificate(ca_cert_file.read())
        except Exception as e:
            logger.error(f'Invalid CA certificate: {str(e)}')
            return jsonify({'error': 'Invalid CA certificate format.'}), 400
        
        try:
            ca_key_pwd = ca_key_password.encode('utf-8') if ca_key_password else None
            ca_private_key = CertificateService.load_private_key(ca_key_file.read(), ca_key_pwd)
        except Exception as e:
            logger.error(f'Invalid CA private key: {str(e)}')
            return jsonify({'error': 'Invalid CA private key or incorrect password.'}), 400
        
        if ca_private_key.public_key() != ca_cert.public_key():
            return jsonify({'error': 'CA private key does not match the CA certificate.'}), 400
        
        try:
            certificate = CertificateService.sign_csr(
                csr, ca_cert.subject, ca_cert.public_key(), ca_private_key, validity_days
            )
        except ValueError as e:
            logger.error(f'Refusing to sign CSR: {str(e)}')
            return jsonify({'error': 'The CSR signature is invalid.'}), 400
        cert_pem = CertificateService.serialize_certificate(certificate)
        
        return send_file(
            io.BytesIO(cert_pem.encode('utf-8')),
            mimetype='application/x-pem-file',
            as_attachment=True,
            download_name='certificate.crt'
        )
    
    except Exception as e:
        logger.error(f'Error signing CSR: {str(e)}')
        return jsonify({'error': 'An error occurred while signing the CSR.'}), 500
