"""One-client TLS chat server."""

import datetime
import ipaddress
import ssl
import socket

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts.messenger import BasicMessenger, DATA_DIR, ensure_data_dir, receive_frame, send_frame


class Server(BasicMessenger):
    def generate_symmetric_key(self):
        return Fernet.generate_key()

    def save_symmetric_key(self):
        ensure_data_dir()
        key_path = DATA_DIR / "symmetric.key"
        key_path.write_bytes(self.symmetric_key)
        key_path.chmod(0o600)

    def save_public_key(self):
        ensure_data_dir()
        (DATA_DIR / "server_public.pem").write_bytes(self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    def read_client_public_key(self):
        return serialization.load_pem_public_key((DATA_DIR / "client_public.pem").read_bytes())

    def create_certificate(self):
        """Create a fresh certificate for this local server session."""
        ensure_data_dir()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
            ]), critical=False)
            .sign(key, hashes.SHA256())
        )
        key_path = DATA_DIR / "server.key"
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
        key_path.chmod(0o600)
        (DATA_DIR / "server.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    def start_connection(self):
        self.create_certificate()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(DATA_DIR / "server.crt", DATA_DIR / "server.key")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(1)
            print(f"Server listening on {self.host}:{listener.getsockname()[1]}", flush=True)
            client, address = listener.accept()
            with context.wrap_socket(client, server_side=True) as channel:
                print(f"Connected to {address}")
                self.handle_messaging(channel)

    def handle_messaging(self, channel):
        peer_key = self.read_client_public_key() if self.mode == "asymmetric" else None
        while (payload := receive_frame(channel)) is not None:
            message = self.decode_message(payload)
            print(f"Client: {message}")
            if message == "bye":
                break
            response = input("Reply: ")
            send_frame(channel, self.encode_message(response, peer_key))
            if response == "bye":
                break
