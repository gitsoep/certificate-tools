from flask import Flask, render_template, request, jsonify
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import configparser
import os

app = Flask(__name__)

def load_config_defaults():
    defaults = {
        'country': 'NL',
        'state': 'Gelderland',
        'locality': 'Nijmegen',
        'organization': 'Mosadex Services B.V.',
        'organizational_unit': 'Example',
        'common_name': 'Mosadex ExampleService PRD',
        'email': 'example@mosadex-services.nl',
        'key_size': '4096'
    }
    return defaults

CONFIG_DEFAULTS = load_config_defaults()

@app.route('/')
def index():
    return render_template('index.html', defaults=CONFIG_DEFAULTS)

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
        key_size = int(request.form.get('key_size', CONFIG_DEFAULTS['key_size']))

        # Validate required fields
        if not common_name:
            return jsonify({'error': 'Common Name is required'}), 400

        # Generate private key
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
        
        # Add extended key usage for client authentication
        csr_builder = csr_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        
        # Generate CSR
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

        # Serialize private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # Serialize CSR to PEM format
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        return render_template('result.html', 
                             private_key=private_key_pem, 
                             csr=csr_pem)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
