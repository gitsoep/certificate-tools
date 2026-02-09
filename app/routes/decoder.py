"""
Certificate and CSR decoder routes
"""
import logging
from flask import Blueprint, render_template, request, jsonify, session, current_app
from ..services.certificate import CertificateService

bp = Blueprint('decoder', __name__)
logger = logging.getLogger(__name__)


@bp.route('/decoder')
def decoder():
    """Decoder page."""
    user = session.get("user")
    return render_template('decoder.html',
                         active_page='decoder',
                         user=user,
                         app_title=current_app.config['APP_TITLE'])


@bp.route('/decode-csr', methods=['POST'])
def decode_csr():
    """Decode a CSR or certificate."""
    try:
        csr_file = request.files.get('csr_file')
        csr_text = request.form.get('csr_text', '')
        
        if csr_file:
            data = csr_file.read()
        elif csr_text:
            data = csr_text.encode('utf-8')
        else:
            return jsonify({'error': 'CSR/Certificate file or text is required'}), 400
        
        # Try parsing as certificate first
        is_certificate = False
        cert_obj = None
        csr_obj = None
        
        try:
            cert_obj = CertificateService.load_certificate(data)
            is_certificate = True
        except Exception:
            try:
                csr_obj = CertificateService.load_csr(data)
            except Exception:
                return jsonify({'error': 'Invalid CSR or Certificate format'}), 400
        
        if is_certificate:
            subject_info = CertificateService.extract_subject_info(cert_obj)
            issuer_info = CertificateService.extract_issuer_info(cert_obj)
            key_info = CertificateService.extract_public_key_info(cert_obj)
            extensions_info, eku, san, key_usage, basic_constraints = CertificateService.extract_extensions_info(cert_obj)
            
            validity_info = {
                'not_before': cert_obj.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'not_after': cert_obj.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
            }
            
            return jsonify({
                'is_certificate': True,
                'subject': subject_info,
                'issuer': issuer_info,
                'validity': validity_info,
                'public_key': key_info,
                'extensions': extensions_info,
                'signature_algorithm': cert_obj.signature_algorithm_oid._name,
                'key_algorithm': key_info['type'],
                'key_size': key_info['size'],
                'extended_key_usage': eku,
                'subject_alternative_names': san,
                'key_usage': key_usage,
                'basic_constraints': basic_constraints
            })
        else:
            subject_info = CertificateService.extract_subject_info(csr_obj)
            key_info = CertificateService.extract_public_key_info(csr_obj)
            extensions_info, eku, san, key_usage, basic_constraints = CertificateService.extract_extensions_info(csr_obj)
            
            return jsonify({
                'is_certificate': False,
                'subject': subject_info,
                'public_key': key_info,
                'extensions': extensions_info,
                'signature_algorithm': csr_obj.signature_algorithm_oid._name,
                'key_algorithm': key_info['type'],
                'key_size': key_info['size'],
                'extended_key_usage': eku,
                'subject_alternative_names': san,
                'key_usage': key_usage,
                'basic_constraints': basic_constraints
            })
    
    except Exception as e:
        logger.error(f'Error decoding CSR: {str(e)}')
        return jsonify({'error': 'An error occurred while decoding.'}), 500
