# Secure Messaging Demo

A two-terminal Python chat demo over TLS. It supports plain messages inside TLS, Fernet encryption, and RSA-OAEP encryption. The extra encryption modes demonstrate cryptographic APIs; TLS already protects the connection.

## Requirements

- Python 3.11 or newer
- [`cryptography`](https://cryptography.io/en/latest/)

If Pipenv is installed, install dependencies with:

```bash
pipenv install
```

Or use a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install cryptography
```

## Run

From the repository root, start the server in one terminal:

```bash
pipenv run python main.py server none
```

Start the client in another terminal:

```bash
pipenv run python main.py client none
```

Replace `none` in **both** commands with `symmetric` or `asymmetric` to try another mode. If you installed into a virtual environment instead of Pipenv, use `python main.py ...`. You can also run `python main.py` and answer the prompts.

Type a message in the client and a reply in the server terminal. Type `bye` on either side to end the session. Start a new server process for another conversation. The app listens on `localhost:65432`; both processes must run on the same machine and share the repository's `.runtime` directory.

The server generates a fresh local TLS certificate at startup. The client checks that certificate and its `localhost` name. Start the client after the server prints `Server listening`. Symmetric and public key material is also created in `.runtime`, which Git ignores. No OpenSSL setup is needed.

## Project layout

| Path | Purpose |
| --- | --- |
| `main.py` | Command line entry point and mode setup |
| `scripts/messenger.py` | Message framing and encryption helpers |
| `scripts/server.py` | One-client TLS server |
| `scripts/client.py` | TLS client |
| `architecture.md` | Design and protocol notes |

## Notes

This is a local educational demo, not a multi-user messenger. RSA-OAEP accepts only short messages (190 bytes with the 2048-bit key used here). The client trusts the certificate file in the shared runtime directory; this setup is intended for processes on one machine. The server handles one client per run.

Generated keys and certificates live in `.runtime` and are ignored by Git. Old demo keys have been removed from the repository history; existing clones may still contain copies.
