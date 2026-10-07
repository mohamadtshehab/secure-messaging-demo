"""Shared transport and encryption helpers for the local chat demo."""

import os
import struct
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


DATA_DIR = Path(os.environ.get("ISS_DATA_DIR", Path(__file__).resolve().parents[1] / ".runtime"))
MAX_FRAME = 64 * 1024


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    DATA_DIR.chmod(0o700)


def send_frame(channel, payload):
    if len(payload) > MAX_FRAME:
        raise ValueError("Message is too large")
    channel.sendall(struct.pack("!I", len(payload)) + payload)


def receive_frame(channel):
    def read_exactly(size):
        data = bytearray()
        while len(data) < size:
            chunk = channel.recv(size - len(data))
            if not chunk:
                if not data:
                    return None
                raise ConnectionError("Connection closed during a message")
            data.extend(chunk)
        return bytes(data)

    header = read_exactly(4)
    if header is None:
        return None
    size = struct.unpack("!I", header)[0]
    if size > MAX_FRAME:
        raise ValueError("Incoming message is too large")
    payload = read_exactly(size)
    if payload is None:
        raise ConnectionError("Connection closed during a message")
    return payload


class BasicMessenger:
    def __init__(self, host="localhost", port=65432, mode="none"):
        if mode not in {"none", "symmetric", "asymmetric"}:
            raise ValueError("Mode must be none, symmetric, or asymmetric")
        self.host = host
        self.port = port
        self.mode = mode
        self.symmetric_key = None
        self.private_key = None
        self.public_key = None

    def encrypt_symmetric(self, message):
        if self.symmetric_key is None:
            raise ValueError("Symmetric key is not set")
        return Fernet(self.symmetric_key).encrypt(message.encode())

    def decrypt_symmetric(self, payload):
        if self.symmetric_key is None:
            raise ValueError("Symmetric key is not set")
        return Fernet(self.symmetric_key).decrypt(payload).decode()

    def generate_private_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def generate_public_key(self, private_key):
        return private_key.public_key()

    def encrypt_asymmetric(self, message, public_key):
        return public_key.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    def decrypt_asymmetric(self, payload):
        if self.private_key is None:
            raise ValueError("Private key is not set")
        return self.private_key.decrypt(
            payload,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        ).decode()

    def encode_message(self, message, peer_public_key=None):
        if self.mode == "symmetric":
            return self.encrypt_symmetric(message)
        if self.mode == "asymmetric":
            return self.encrypt_asymmetric(message, peer_public_key)
        return message.encode()

    def decode_message(self, payload):
        if self.mode == "symmetric":
            return self.decrypt_symmetric(payload)
        if self.mode == "asymmetric":
            return self.decrypt_asymmetric(payload)
        return payload.decode()
