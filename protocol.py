import rsa
import logging
from socket import socket
from typing import final
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Connection Fields
ADDRESS: final = "0.0.0.0"
PORT: final = 9999

LENGTH_FIELD_SIZE: final = 3

# Encryption Fields
SALT: final = b'u&\xb3[\xdf\x15\xe6\xd1\x83\xf5\x8cp?OAB'
PUBLIC_KEY_SIZE: final = 2048

# Available commands in the server
COMMANDS = ('HELP', 'Help', 'help', 'LS', 'Ls', 'ls', 'PUT', 'Put', 'put', 'GET', 'Get', 'get', 'QUIT', 'Quit', 'quit')


def init_keys() -> (rsa.PublicKey, rsa.PrivateKey):
    """ Create a public and a private key to exchange the symmetric key """
    return rsa.newkeys(PUBLIC_KEY_SIZE)


def encrypt_with_public_key(message: bytes, public_key: rsa.PublicKey) -> bytes:
    """ Encrypt a message using the public key """
    encrypted_message = rsa.encrypt(message=message, pub_key=public_key)
    return (str(len(encrypted_message)).zfill(LENGTH_FIELD_SIZE)).encode() + encrypted_message


def decrypt_with_private_key(enc_msg: bytes, private_key: rsa.PrivateKey) -> (bool, str):
    """ Decrypt the message using the private key """
    length = enc_msg[0:3].decode()
    if length.isdigit():
        try:
            decrypted_message = rsa.decrypt(crypto=enc_msg[3:], priv_key=private_key)
            return True, decrypted_message

        except rsa.pkcs1.DecryptionError:
            return False, 'Symmetric Key Has Been Corrupted'
    else:
        return False, 'Error'


def generate_symmetric_key():
    """ Generate a 32 bytes symmetric key """
    return get_random_bytes(32)


def create_msg(data: str, symmetric_key: bytes) -> bytes:
    """ Add a length field of the message length, encrypt the message and return a bytes stream which consist of
    the length field + encrypted message """
    cipher = AES.new(key=symmetric_key, mode=AES.MODE_EAX, nonce=SALT)
    encrypted_msg = cipher.encrypt(data.encode())
    return (str(len(encrypted_msg)).zfill(LENGTH_FIELD_SIZE)).encode() + encrypted_msg


def get_msg(client_socket: socket, symmetric_key: bytes) -> (bool, str):
    """ Extract message using the length field, decrypt it and return the message if it's valid """
    length = client_socket.recv(LENGTH_FIELD_SIZE).decode()
    if length.isdigit():
        cipher = AES.new(key=symmetric_key, mode=AES.MODE_EAX, nonce=SALT)
        message = cipher.decrypt(client_socket.recv(int(length))).decode()
        return True, message
    else:
        return False, "Error"


def create_file_request(file_name: str, symmetric_key) -> bytes:
    """ Create a packet with all length and size values of the file name and file size
    The packet will contain the following field: length of file-name, file-name, size of the file in bytes, the amount
    of digits of the file-size - for example if the file-size is 500kb then this field will contain '007', and finally
    the encrypted file content.

    The final packet will look like this -

                {Field Number 1}     {Field Number 2}    {Field Number 3}      {Field N. 4}       {Field Number 5}

     Length:    [LENGTH_FIELD_SIZE]  [Field Number 1]   [LENGTH_FIELD_SIZE]  [Field Number 3]     [Field Number 4]
     Description: L=<file-name length> N=<file name>     D=<digits length>    S=<file size>        C=<file content>
    """

    try:
        with open(file_name, 'rb') as file:
            file_content = file.read()

    except FileNotFoundError:
        return b'File Not Found'

    file_size = str(len(file_content))
    digits_length = len(file_size)
    cipher = AES.new(key=symmetric_key, mode=AES.MODE_EAX, nonce=SALT)
    encrypted_file = cipher.encrypt(file_content)
    return (str(len(file_name)).zfill(LENGTH_FIELD_SIZE).encode() + file_name.encode()
            + (str(digits_length)).zfill(LENGTH_FIELD_SIZE).encode() + file_size.encode() + encrypted_file)


def get_file_response(server_socket: socket, symmetric_key: bytes):
    """ Create a packet with all length and size values of the file name and file size
    The packet will contain the following field: length of file-name, file-name, size of the file in bytes, the amount
    of digits of the file-size - for example if the file-size is 500kb then this field will contain '007', and finally
    the encrypted file content.

    The final packet will look like this -

                {Field Number 1}     {Field Number 2}    {Field Number 3}      {Field N. 4}       {Field Number 5}

     Length:    [LENGTH_FIELD_SIZE]  [Field Number 1]   [LENGTH_FIELD_SIZE]  [Field Number 3]     [Field Number 4]
     Description: L=<file-name length> N=<file name>     D=<digits length>    S=<file size>        C=<file content>
    """

    file_name_length = server_socket.recv(LENGTH_FIELD_SIZE).decode()
    if file_name_length.isdigit():
        file_name = server_socket.recv(int(file_name_length)).decode()
        digits_length = server_socket.recv(LENGTH_FIELD_SIZE).decode()

        if digits_length.isdigit():
            file_size = server_socket.recv(int(digits_length)).decode()
            encrypted_content = server_socket.recv(int(file_size))
            cipher = AES.new(key=symmetric_key, mode=AES.MODE_EAX, nonce=SALT)

            with open(file_name, 'w') as file:
                file.write(cipher.decrypt(encrypted_content).decode())

            return True, 'Operation Succeed'

        else:
            error_msg = 'Digits length field missing'
            logging.info(error_msg)
            return False, error_msg

    else:
        error_msg = 'File name field missing'
        logging.info(error_msg)
        return False, error_msg
