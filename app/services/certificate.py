"""
Certificate operations service
"""
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class CertificateService:
    """Service for certificate-related operations."""
    
    EKU_MAP = {
        'serverAuth': x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        'clientAuth': x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        'codeSigning': x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
        'emailProtection': x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
        'timeStamping': x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
        'ocspSigning': x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING
    }
    
    EKU_DISPLAY_NAMES = {
        'serverAuth': 'Server Authentication',
        'clientAuth': 'Client Authentication',
        'codeSigning': 'Code Signing',
        'emailProtection': 'Email Protection',
        'timeStamping': 'Time Stamping',
        'ocspSigning': 'OCSP Signing'
    }
    
    @staticmethod
    def generate_private_key(signature_algorithm: str, key_size: int = 4096):
        """Generate a private key based on the signature algorithm."""
        if signature_algorithm.startswith('ECDSA'):
            curves = {
                'ECDSA_SHA256': ec.SECP256R1(),
                'ECDSA_SHA384': ec.SECP384R1(),
                'ECDSA_SHA512': ec.SECP521R1()
            }
            curve = curves.get(signature_algorithm, ec.SECP256R1())
            return ec.generate_private_key(curve, default_backend())
        elif signature_algorithm == 'Ed25519':
            return ed25519.Ed25519PrivateKey.generate()
        elif signature_algorithm == 'Ed448':
            return ed448.Ed448PrivateKey.generate()
        else:
            return rsa.generate_private_key(
                public_exponent=65537, key_size=key_size, backend=default_backend()
            )
    
    @staticmethod
    def load_private_key(key_data: bytes, password: bytes = None):
        """Load a private key from PEM data."""
        return serialization.load_pem_private_key(key_data, password=password, backend=default_backend())
    
    @staticmethod
    def serialize_private_key(private_key) -> str:
        """Serialize a private key to PEM format."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    @staticmethod
    def get_hash_algorithm(signature_algorithm: str):
        """Get the hash algorithm for the given signature algorithm."""
        if signature_algorithm in ('Ed25519', 'Ed448'):
            return None
        elif signature_algorithm in ('SHA384', 'ECDSA_SHA384'):
            return hashes.SHA384()
        elif signature_algorithm in ('SHA512', 'ECDSA_SHA512'):
            return hashes.SHA512()
        return hashes.SHA256()
    
    @staticmethod
    def build_subject_name(country: str, state: str = None, locality: str = None,
                           organization: str = None, organizational_unit: str = None,
                           common_name: str = None, email: str = None) -> x509.Name:
        """Build an X.509 Name from the provided attributes."""
        attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, country)]
        if state:
            attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if organization:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if organizational_unit:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
        if common_name:
            attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        if email:
            attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        return x509.Name(attrs)
    
    @staticmethod
    def build_csr(subject_name: x509.Name, private_key, eku_selection: str, hash_algorithm):
        """Build and sign a CSR."""
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject_name)
        csr_builder = csr_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False
            ),
            critical=True
        )
        if eku_selection in CertificateService.EKU_MAP:
            csr_builder = csr_builder.add_extension(
                x509.ExtendedKeyUsage([CertificateService.EKU_MAP[eku_selection]]),
                critical=False
            )
        return csr_builder.sign(private_key, hash_algorithm, default_backend())
    
    @staticmethod
    def load_certificate(cert_data: bytes) -> x509.Certificate:
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    
    @staticmethod
    def load_der_certificate(cert_data: bytes) -> x509.Certificate:
        return x509.load_der_x509_certificate(cert_data, default_backend())
    
    @staticmethod
    def load_csr(csr_data: bytes) -> x509.CertificateSigningRequest:
        return x509.load_pem_x509_csr(csr_data, default_backend())
    
    @staticmethod
    def serialize_certificate(certificate: x509.Certificate) -> str:
        return certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    @staticmethod
    def serialize_csr(csr: x509.CertificateSigningRequest) -> str:
        return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    @staticmethod
    def extract_subject_info(obj) -> dict:
        """Extract subject information from a certificate or CSR."""
        info = {
            'commonName': None, 'organizationName': None, 'organizationalUnitName': None,
            'countryName': None, 'stateOrProvinceName': None, 'localityName': None, 'emailAddress': None
        }
        for attr in obj.subject:
            if attr.oid._name in info:
                info[attr.oid._name] = attr.value
        info['organization'] = info.get('organizationName')
        return info
    
    @staticmethod
    def extract_issuer_info(cert) -> dict:
        """Extract issuer information from a certificate."""
        info = {
            'commonName': None, 'organizationName': None, 'organizationalUnitName': None,
            'countryName': None, 'stateOrProvinceName': None, 'localityName': None
        }
        for attr in cert.issuer:
            if attr.oid._name in info:
                info[attr.oid._name] = attr.value
        info['organization'] = info.get('organizationName')
        return info
    
    @staticmethod
    def extract_public_key_info(obj) -> dict:
        """Extract public key information."""
        public_key = obj.public_key()
        key_info = {'type': type(public_key).__name__, 'size': None}
        if hasattr(public_key, 'key_size'):
            key_info['size'] = public_key.key_size
        return key_info
    
    @staticmethod
    def extract_extensions_info(obj) -> tuple:
        """Extract extension information. Returns (extensions, eku, san, key_usage, basic_constraints)."""
        extensions_info = []
        eku = san = key_usage = basic_constraints = None
        
        for ext in obj.extensions:
            ext_name = ext.oid._name
            ext_value = str(ext.value)
            
            if isinstance(ext.value, x509.KeyUsage):
                usage = []
                if ext.value.digital_signature: usage.append('Digital Signature')
                if ext.value.key_encipherment: usage.append('Key Encipherment')
                if ext.value.content_commitment: usage.append('Content Commitment')
                if ext.value.data_encipherment: usage.append('Data Encipherment')
                if ext.value.key_agreement: usage.append('Key Agreement')
                if ext.value.key_cert_sign: usage.append('Key Cert Sign')
                if ext.value.crl_sign: usage.append('CRL Sign')
                ext_value = ', '.join(usage)
                key_usage = ext_value
            elif isinstance(ext.value, x509.ExtendedKeyUsage):
                names = [CertificateService.EKU_DISPLAY_NAMES.get(o._name, o._name) for o in ext.value]
                ext_value = ', '.join(names)
                eku = ext_value
            elif isinstance(ext.value, x509.SubjectAlternativeName):
                ext_value = ', '.join(str(n.value) for n in ext.value)
                san = ext_value
            elif isinstance(ext.value, x509.BasicConstraints):
                parts = [f"CA: {ext.value.ca}"]
                if ext.value.path_length is not None:
                    parts.append(f"Path Length: {ext.value.path_length}")
                ext_value = ', '.join(parts)
                basic_constraints = ext_value
            elif isinstance(ext.value, x509.AuthorityKeyIdentifier):
                parts = []
                if ext.value.key_identifier:
                    parts.append(f"Key ID: {ext.value.key_identifier.hex(':').upper()}")
                ext_value = '\n'.join(parts) if parts else 'None'
            elif isinstance(ext.value, x509.SubjectKeyIdentifier):
                ext_value = ext.value.digest.hex(':').upper()
            
            extensions_info.append({'name': ext_name, 'critical': ext.critical, 'value': ext_value})
        
        return extensions_info, eku, san, key_usage, basic_constraints
