import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    f = open("auth/cacsertificate.crt", "rb")
    ca_cert_raw = f.read()
    ca_cert = x509.load_pem_x509_certificate(
        data=ca_cert_raw, backend=default_backend()
    )
    ca_public_key = ca_cert.public_key()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        # MODE 3 -- send to server
        s.sendall(convert_int_to_bytes(3))
        auth_message = "Client Request SecureStore ID"
        auth_message_bytes = bytes(auth_message, encoding="utf8")
        s.sendall(convert_int_to_bytes(len(auth_message_bytes)))
        s.sendall(auth_message_bytes)

        signed_message_length = convert_bytes_to_int(read_bytes(s, 8))
        signed_message = read_bytes(s, signed_message_length)
        crt_file_data_length = convert_bytes_to_int(read_bytes(s, 8))
        crt_file_data = read_bytes(s, crt_file_data_length)

        server_cert = x509.load_pem_x509_certificate(
            data=crt_file_data, backend=default_backend()
        )
        server_public_key = server_cert.public_key()
        assert (
            server_cert.not_valid_before
            <= datetime.utcnow()
            <= server_cert.not_valid_after
        )

        f = open("auth/cacsertificate.crt", "rb")
        ca_cert_raw = f.read()
        ca_cert = x509.load_pem_x509_certificate(
            data=ca_cert_raw, backend=default_backend()
        )
        ca_public_key = ca_cert.public_key()

        ca_public_key.verify(
            signature=server_cert.signature,  # signature bytes to  verify
            data=server_cert.tbs_certificate_bytes,  # certificate data bytes that was signed by CA
            padding=padding.PKCS1v15(),  # padding used by CA bot to sign the the server's csr
            algorithm=server_cert.signature_hash_algorithm,
        )

        server_public_key.verify(
            signed_message,
            auth_message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        # will continue here if the verify above passes

        while True:

            print("Handshake complete")
            filename = input("Enter a filename to send (enter -1 to exit):").strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                print(f"{len(data) = }")
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))

                for i in range(0, len(data), 62):

                    block = data[i : i + 62]
                    encrypted_message = server_public_key.encrypt(
                        block,
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    s.sendall(convert_int_to_bytes(len(encrypted_message)))
                    s.sendall(encrypted_message)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
