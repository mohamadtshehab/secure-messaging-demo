"""TLS chat client."""

import socket
import ssl

from cryptography.hazmat.primitives import serialization

from scripts.messenger import BasicMessenger, DATA_DIR, ensure_data_dir, receive_frame, send_frame


class Client(BasicMessenger):
    def read_symmetric_key(self):
        return (DATA_DIR / "symmetric.key").read_bytes()

    def read_server_public_key(self):
        return serialization.load_pem_public_key((DATA_DIR / "server_public.pem").read_bytes())

    def save_public_key(self):
        ensure_data_dir()
        (DATA_DIR / "client_public.pem").write_bytes(self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    def connect(self):
        context = ssl.create_default_context(cafile=str(DATA_DIR / "server.crt"))
        with socket.create_connection((self.host, self.port)) as connection:
            with context.wrap_socket(connection, server_hostname=self.host) as channel:
                print("Connected to server.")
                self.handle_connection(channel)

    def handle_connection(self, channel):
        peer_key = self.read_server_public_key() if self.mode == "asymmetric" else None
        while True:
            message = input("Message: ")
            send_frame(channel, self.encode_message(message, peer_key))
            if message == "bye":
                break
            payload = receive_frame(channel)
            if payload is None:
                break
            response = self.decode_message(payload)
            print(f"Server: {response}")
            if response == "bye":
                break
