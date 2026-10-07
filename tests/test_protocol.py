"""Protocol and encryption checks that do not need an open network port."""

import unittest

from cryptography.fernet import Fernet

from scripts.messenger import BasicMessenger, receive_frame, send_frame


class ChunkedChannel:
    def __init__(self):
        self.data = bytearray()

    def sendall(self, data):
        self.data.extend(data)

    def recv(self, size):
        chunk = bytes(self.data[:min(size, 3)])
        del self.data[:len(chunk)]
        return chunk


class ProtocolTests(unittest.TestCase):
    def test_framing_survives_partial_reads(self):
        channel = ChunkedChannel()
        send_frame(channel, b'first')
        send_frame(channel, b'second')
        self.assertEqual(receive_frame(channel), b'first')
        self.assertEqual(receive_frame(channel), b'second')
        self.assertIsNone(receive_frame(channel))

    def test_all_modes_round_trip(self):
        for mode in ('none', 'symmetric', 'asymmetric'):
            with self.subTest(mode=mode):
                sender = BasicMessenger(mode=mode)
                receiver = BasicMessenger(mode=mode)
                peer_key = None
                if mode == 'symmetric':
                    sender.symmetric_key = receiver.symmetric_key = Fernet.generate_key()
                if mode == 'asymmetric':
                    receiver.private_key = receiver.generate_private_key()
                    peer_key = receiver.generate_public_key(receiver.private_key)
                payload = sender.encode_message('hello', peer_key)
                self.assertEqual(receiver.decode_message(payload), 'hello')


if __name__ == '__main__':
    unittest.main()
