"""Launch one side of the local secure messaging demo."""

import argparse

from scripts.client import Client
from scripts.server import Server


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", nargs="?", choices=["server", "client"])
    parser.add_argument("mode", nargs="?", choices=["none", "symmetric", "asymmetric"])
    args = parser.parse_args(argv)
    role = args.role or input("Run as (server/client): ").strip().lower()
    mode = args.mode or input("Encryption (none/symmetric/asymmetric): ").strip().lower()
    if role not in {"server", "client"} or mode not in {"none", "symmetric", "asymmetric"}:
        parser.error("choose a valid role and encryption mode")

    if role == "server":
        server = Server(mode=mode)
        if mode == "symmetric":
            server.symmetric_key = server.generate_symmetric_key()
            server.save_symmetric_key()
        elif mode == "asymmetric":
            server.private_key = server.generate_private_key()
            server.public_key = server.generate_public_key(server.private_key)
            server.save_public_key()
        server.start_connection()
    else:
        client = Client(mode=mode)
        if mode == "symmetric":
            client.symmetric_key = client.read_symmetric_key()
        elif mode == "asymmetric":
            client.private_key = client.generate_private_key()
            client.public_key = client.generate_public_key(client.private_key)
            client.save_public_key()
        client.connect()


if __name__ == "__main__":
    main()
