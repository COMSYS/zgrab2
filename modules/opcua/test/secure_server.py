#!/usr/bin/env python3
#!/usr/bin/env python3
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID
from opcua import ua, Server
from opcua.server.user_manager import UserManager


def create_key_pair():
    print("Generating new key pair for testing")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    with open("server_key.pem", "wb") as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.NoEncryption()))
    subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = x509.CertificateBuilder(
        issuer_name=issuer,
        subject_name=subject,
        public_key=key.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.datetime.utcnow(),
        not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(weeks=104)
    ).sign(key, hashes.SHA256(), default_backend())
    with open("server_cert.pem", "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))


if __name__ == "__main__":
    endpointUrl = sys.argv[1]
    server = Server()
    server.set_endpoint(endpointUrl)

    if not os.path.isfile("server_cert.pem"):
        create_key_pair()

    server.load_certificate("server_cert.pem")
    server.load_private_key("server_key.pem")
    server.set_security_policy([
        ua.SecurityPolicyType.Basic128Rsa15_SignAndEncrypt,
        ua.SecurityPolicyType.Basic256_SignAndEncrypt,
    ])

    def user_manager(isession, username, password):
        isession.user = UserManager.User
        return username == "user" and password == "1234"
    server.set_security_IDs(["username"])
    server.user_manager.set_user_manager(user_manager)

    server.start()
