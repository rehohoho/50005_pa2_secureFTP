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


def get_auth_request(client_socket):
    # M1 - from client
    message_len = convert_bytes_to_int(read_bytes(client_socket, 8))
    # M2 - from client
    message = read_bytes(client_socket, message_len)
    print(f"Auth Message from client: {message}")
    return message


def get_server_private_key():
    # Extract keys from PEM
    with open("./auth/server_private_key.pem", mode="r", encoding="utf8") as f:
        private_key = serialization.load_pem_private_key(
            bytes(f.read(), encoding="utf8"),
            password=None,
        )
    # public_key = private_key.public_key()
    return private_key


def get_signed_crt():
    # get the crt data as bytes
    with open("./auth/server_signed.crt", mode="rb") as f:
        crt_file_data = f.read()
    return crt_file_data


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"

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

                            enc_filename = f"enc_recv_{filename.split('/')[-1]}"
                            enc_fp = open(f"recv_files_enc/{enc_filename}", mode="ab")

                            file_data_blocks = []
                            for _ in range(0, file_len, 62):
                                block_len = convert_bytes_to_int(
                                    read_bytes(client_socket, 8)
                                )

                                encrypted_block = read_bytes(client_socket, block_len)
                                enc_fp.write(encrypted_block)
                                print(f"receiving encrypted block... {block_len}")
                                
                                decrypted_message = private_key.decrypt(
                                    encrypted_block,
                                    padding.OAEP(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None,
                                    ),
                                )
                                file_data_blocks.append(decrypted_message)

                            enc_fp.close()

                            # Write the file with 'recv_' prefix
                            filename = "recv_" + filename.split("/")[-1]
                            with open(f"recv_files/{filename}", mode="wb") as fp:
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
                            # Authentication procedure
                            auth_nonce = get_auth_request(client_socket)
                            private_key = get_server_private_key()

                            signed_message = private_key.sign(
                                auth_nonce,  # message in bytes format
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                ),
                                hashes.SHA256(),  # hashing algorithm used to hash the data before encryption
                            )
                            crt_file_data = get_signed_crt()

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
