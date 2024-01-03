"""
    Encrypted ftp-server, client side implementation
    Author: Ishay houri
    Date: 03/06/2023
    Possible client commands defined in protocol.py
"""
import socket
from rsa import PublicKey
import protocol


def main():
    # Create TCP/IP socket object
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Send a request to connect to the server (Client hello)
    my_socket.connect((input("Enter the IP of server: "), protocol.PORT))

    # Get the public key from the server
    public_key = PublicKey.load_pkcs1(my_socket.recv(protocol.PUBLIC_KEY_SIZE))

    # Generate a symmetric key and sent it back to server using the public key (key exchange & Client finished)
    symmetric_key = protocol.generate_symmetric_key()
    key_exchange = protocol.encrypt_with_public_key(symmetric_key, public_key)
    my_socket.send(key_exchange)

    valid, echo = protocol.get_msg(client_socket=my_socket, symmetric_key=symmetric_key)

    # The server got the symmetric key correctly
    if valid:
        print(echo)

        while True:
            user_input = input("Enter a command: \n")

            get_request = protocol.create_msg(data=user_input, symmetric_key=symmetric_key)
            my_socket.send(get_request)

            if user_input.startswith('get'):
                valid, message = protocol.get_msg(client_socket=my_socket, symmetric_key=symmetric_key)

                if valid and message == '226 Transfer Complete.':
                    valid, msg = protocol.get_file_response(server_socket=my_socket, symmetric_key=symmetric_key)

                    # If the file was saved successfully in the client device print '226 Transfer Complete'
                    print(message) if valid else print('Error! Try again.')

                else:
                    print(message)

            elif user_input.startswith('put'):
                # 1. Add length field ("Put file.txt" -> "12Put file.txt") and send it to the server
                _, file_name = user_input.split(' ')
                encrypted_file = protocol.create_file_request(file_name=file_name, symmetric_key=symmetric_key)
                my_socket.send(encrypted_file)
                valid, msg = protocol.get_msg(my_socket, symmetric_key=symmetric_key)

                print(msg) if valid else print('Error! Try again.')

            else:
                valid, echo = protocol.get_msg(client_socket=my_socket, symmetric_key=symmetric_key)

                if valid:
                    print(echo)

                if echo == '221 Goodbye.':
                    break

        # Close socket
        my_socket.close()

    else:
        print('An Error occurred during keys exchange')


if __name__ == "__main__":
    main()
