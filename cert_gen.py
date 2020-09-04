import argparse
import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

YEARS = 365
DEFAULT_RSA_KEYSIZE = 2048
SUBJECT_ATTR = ["CN"]


class CertGen(object):

    def __init__(self, args):
        self.options = args
        self.lifespan = self.options.lifespan or 10 * YEARS


    @staticmethod
    def create_key():
        print("create key")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=DEFAULT_RSA_KEYSIZE,
            backend=default_backend()
        )
        return key

    @staticmethod
    def create_cert_authority(ca_key, subject, lifespan):
        print("create_cert_authority")
        subject_and_issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"UK"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"London"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ORG"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject),
        ])

        ca = x509.CertificateBuilder(
            subject_name=subject_and_issuer,
            issuer_name=subject_and_issuer,
            public_key=ca_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=lifespan),
            not_valid_before=datetime.datetime.utcnow()
        )

        ca = ca.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

        ca_cert = ca.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

        return ca_cert

    def _create_ca(self):
        print("create_ca")

        ca_path = os.path.join(self.options.path, self.options.ca)

        if not os.path.exists(f"{ca_path}.key"):
            print("created")
            ca_key = self.create_key()
            ca_cert = self.create_cert_authority(ca_key, self.options.ca, lifespan=self.lifespan)

            with open(f"{ca_path}.key", "wb") as f:
                f.write(ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(f"{ca_path}.crt", "wb") as f:
                f.write(ca_cert.public_bytes(
                    encoding=serialization.Encoding.PEM,
                ))
        else:
            print("loaded")
            with open(f"{ca_path}.crt", "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            with open(f"{ca_path}.key", "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        return ca_key, ca_cert


    @staticmethod
    def create_cert_request(private_key, common_name, country="UK", company="Test Company"):
        print("create_cert_request")
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name)
            ])).sign(private_key, hashes.SHA256(), default_backend())

        return csr

    @staticmethod
    def sign_cert_request(cert_request, ca_key, ca_cert, lifespan):
        print("sign_cert_request")
        cert = x509.CertificateBuilder(
            subject_name=cert_request.subject,
            issuer_name=ca_cert.subject,
            public_key=cert_request.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=lifespan),
            not_valid_before=datetime.datetime.utcnow()
        )
        print("adding extension")
        cert = cert.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName("*.mycompany"),
                    x509.DNSName("*.mycompany.com"),

                ]), critical=False,
        ).sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

        return cert

    def create_cert(self, subject, ca_cert, ca_key):
        print("create cert")
        user_key = self.create_key()
        cert_request = self.create_cert_request(private_key=user_key, common_name=subject)

        user_cert = self.sign_cert_request(
            cert_request=cert_request, ca_cert=ca_cert, ca_key=ca_key, lifespan=self.lifespan,
        )

        return user_key, user_cert

    def save_key_and_cert(self, key, cert, path, extra_certs=None):
        print("save_key_and_cert")
        with open(path, "wb") as f:
            f.write(cert.public_bytes(
                encoding=serialization.Encoding.PEM,
            ))
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

            if extra_certs:
                for extra_cert in extra_certs:
                    f.write(extra_cert.public_bytes(
                        encoding=serialization.Encoding.PEM,
                    ))

    def create_cert_pem(self, cert_id, ca_cert, ca_key):
        print("create_cert_pem")
        user_key, user_cert = self.create_cert(
            subject=cert_id,
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        pem_path = os.path.join(self.options.path, "{}.pem".format(cert_id))

        # Bundle the CA cert in the pem
        self.save_key_and_cert(cert=user_cert, key=user_key, path=pem_path, extra_certs=[ca_cert])

    def create_cert_set(self):

        ca_key, ca_cert = self._create_ca()

        for subject in self.options.clients:
            self.create_cert_pem(cert_id=subject, ca_cert=ca_cert, ca_key=ca_key)


def main(argv):
    parser = argparse.ArgumentParser()

    parser.add_argument('path', type=str, help='Path where certificates will be placed.')
    parser.add_argument('clients', type=str, nargs="*", help='List of client name certs to be created')
    parser.add_argument('--ca', type=str, default="MyCompany.ca", help='Name for the certificate authority')
    parser.add_argument('--lifespan', type=int, help='Expiry length for the certificates')

    CertGen(parser.parse_args(argv)).create_cert_set()


if __name__ == "__main__":
    main(sys.argv[1:])
