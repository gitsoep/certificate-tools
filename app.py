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
    return render_template('index.html', active_page='home')

@app.route('/csr-generator')
def csr_generator():
    return render_template('csr_generator.html', defaults=CONFIG_DEFAULTS, active_page='csr-generator')

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
            return render_template('result.html', 
                                 private_key=private_key_pem, 
                                 csr=csr_pem,
                                 show_private_key=True)
        else:
            return render_template('result.html', 
                                 csr=csr_pem,
                                 show_private_key=False)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/pfx-converter')
def pfx_converter():
    return render_template('pfx_converter.html', active_page='pfx-converter')

@app.route('/csr-signer')
def csr_signer():
    return render_template('csr_signer.html', active_page='csr-signer')

@app.route('/pfx-to-pem')
def pfx_to_pem():
    return render_template('pfx_to_pem.html', active_page='pfx-to-pem')

@app.route('/csr-decoder')
def csr_decoder():
    return render_template('csr_decoder.html', active_page='csr-decoder')

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
        cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
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
        # Get uploaded files
        private_key_file = request.files.get('private_key')
        certificate_file = request.files.get('certificate')
        chain_file = request.files.get('chain')
        password = request.form.get('password', '')
        
        if not private_key_file or not certificate_file:
            return jsonify({'error': 'Both private key and certificate files are required'}), 400
        
        # Read the files
        private_key_data = private_key_file.read()
        certificate_data = certificate_file.read()
        
        # Load the private key
        try:
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            return jsonify({'error': f'Invalid private key file: {str(e)}'}), 400
        
        # Load the certificate
        try:
            certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())
        except Exception as e:
            return jsonify({'error': f'Invalid certificate file: {str(e)}'}), 400
        
        # Load chain certificates if provided
        chain_certs = None
        if chain_file:
            try:
                chain_data = chain_file.read()
                # Try to load multiple certificates from the chain file
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
                return jsonify({'error': f'Invalid chain file: {str(e)}'}), 400
        
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
