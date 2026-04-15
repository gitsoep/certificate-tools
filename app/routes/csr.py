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
            key_size = int(request.form.get('key_size', defaults['key_size']))
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
                                 show_private_key=True,
                                 user=session.get("user"),
                                 app_title=current_app.config['APP_TITLE'])
        else:
            return render_template('csr-generator-result.html',
                                 csr=csr_pem,
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
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from flask import send_file
        import io
        
        csr_file = request.files.get('csr')
        ca_cert_file = request.files.get('ca_cert')
        ca_key_file = request.files.get('ca_key')
        ca_key_password = request.form.get('ca_key_password', '')
        validity_days = int(request.form.get('validity_days', 365))
        
        if not csr_file:
            return jsonify({'error': 'CSR file is required'}), 400
        
        try:
            csr = CertificateService.load_csr(csr_file.read())
        except Exception as e:
            logger.error(f'Invalid CSR file: {str(e)}')
            return jsonify({'error': 'Invalid CSR file format.'}), 400
        
        if ca_cert_file and ca_key_file:
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
            
            issuer = ca_cert.subject
            signing_key = ca_private_key
        else:
            signing_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            issuer = csr.subject
        
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(csr.subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(csr.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        cert_builder = cert_builder.not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=validity_days)
        )
        
        for extension in csr.extensions:
            # Skip AKI and SKI from CSR - they must be derived from the actual signing CA
            if isinstance(extension.value, (x509.AuthorityKeyIdentifier, x509.SubjectKeyIdentifier)):
                continue
            cert_builder = cert_builder.add_extension(extension.value, critical=extension.critical)
        
        # Add correct Subject Key Identifier derived from the new certificate's public key
        try:
            cert_builder = cert_builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False
            )
        except ValueError:
            pass
        
        # Add correct Authority Key Identifier derived from the signing key
        try:
            cert_builder = cert_builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
                critical=False
            )
        except ValueError:
            pass
        
        try:
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
        except ValueError:
            pass
        
        certificate = cert_builder.sign(signing_key, hashes.SHA256(), default_backend())
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
