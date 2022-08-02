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
    address = args[1] if len(args) > 1 else "localhost"

    file_data_blocks = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(client_socket, filename_len).decode(
                                "utf-8"
                            )
                            print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )

                            for _ in range(0, file_len, 62):
                                block_len = convert_bytes_to_int(
                                    read_bytes(client_socket, 8)
                                )
                                print(block_len)

                                encrypted_block = read_bytes(client_socket, block_len)
                                print("receiving encrypted block...")
                                decrypted_message = private_key.decrypt(
                                    encrypted_block,
                                    padding.OAEP(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None,
                                    ),
                                )
                                file_data_blocks.append(decrypted_message)

                            filename = "recv_" + filename.split("/")[-1]

                            # Write the file with 'recv_' prefix
                            with open(f"recv_files_enc/{filename}", mode="wb") as fp:
                                fp.write(b"".join(file_data_blocks))
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )

                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        case 3:
                            print("auth case -3")
                            # For Auth

                            # M1 - from client
                            message_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )

                            # M2 - from client
                            message = read_bytes(client_socket, message_len).decode(
                                "utf-8"
                            )
                            print(f"Auth Message from client {message}")

                            # Extract private and public keys from PEM
                            try:
                                with open(
                                    "./auth/server_private_key.pem",
                                    mode="r",
                                    encoding="utf8",
                                ) as key_file:
                                    private_key = serialization.load_pem_private_key(
                                        bytes(key_file.read(), encoding="utf8"),
                                        password=None,
                                    )
                                # public_key = private_key.public_key()
                            except Exception as e:
                                print(e)

                            auth_message_bytes = bytes(message, encoding="utf-8")
                            signed_message = private_key.sign(
                                auth_message_bytes,  # message in bytes format
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                ),
                                hashes.SHA256(),  # hashing algorithm used to hash the data before encryption
                            )

                            # get the crt data as bytes
                            try:
                                with open(
                                    "./auth/server_signed.crt", mode="rb"
                                ) as crt_file:
                                    crt_file_data = crt_file.read()
                            except Exception as e:
                                print(e)

                            client_socket.sendall(
                                convert_int_to_bytes(len(signed_message))
                            )
                            client_socket.sendall(signed_message)
                            client_socket.sendall(
                                convert_int_to_bytes(len(crt_file_data))
                            )
                            client_socket.sendall(crt_file_data)

    except Exception as e:
        print(e)
        s.close()


if __name__ == "__main__":
    main(sys.argv[1:])