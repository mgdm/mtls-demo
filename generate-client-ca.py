import datetime
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

PASSPHRASE = b"changeit"
CLIENT_NAME = "wifi-client"

# Generate a private key to use for the client CA
root_ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

os.makedirs("ca/client", exist_ok=True)

with open("ca/client/root-ca.key", "wb") as f:
    f.write(
        root_ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(PASSPHRASE),
        )
    )

ca_subject = ca_issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "City of Aberdeen"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Aberdeen"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ]
)

root_ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_issuer)
    .public_key(root_ca_private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(
        # Our certificate will be valid for ~10 years
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=365 * 10)
    )
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(root_ca_private_key.public_key()),
        critical=False,
    )
    .sign(root_ca_private_key, hashes.SHA256())
)

with open("ca/client/root-ca.pem", "wb") as f:
    f.write(root_ca_cert.public_bytes(serialization.Encoding.PEM))

# We have a self-signed root CA for the client side
# We can add this to our server's trust store so that it trusts the clients properly

# Normally you might next go and issue intermediates
# The idea here is that you keep your root private key offline or in an HSM or whatever
# and occasionally take it out to generate new intermediates, which you sign from
# If the intermediate is compromised, you just create a new one, revoke the old, and carry on
# Your clients should just trust the root CA certificate

# We'll skip this and just issue straight from the root

ee_key = ec.generate_private_key(ec.SECP256R1())

subject = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "City of Aberdeen"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Aberdeen"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        # Common name in here is how the cert will be identified, unlike a server cert
        x509.NameAttribute(NameOID.COMMON_NAME, CLIENT_NAME),
    ]
)

ee_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(root_ca_cert.subject)
    .public_key(ee_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(
        # Our cert will be valid for 1 year
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=365)
    )
    # Note there is no SubjectAlternativeName extension for the client certificate
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.ExtendedKeyUsage(
            [
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                # x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]
        ),
        critical=False,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            root_ca_cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
        ),
        critical=False,
    )
    .sign(root_ca_private_key, hashes.SHA256())
)

with open("ca/client/client.pem", "wb") as f:
    f.write(ee_cert.public_bytes(serialization.Encoding.PEM))

with open("ca/client/client.key", "wb") as f:
    f.write(
        ee_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(PASSPHRASE),
        )
    )
