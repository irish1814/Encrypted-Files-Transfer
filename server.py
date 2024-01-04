import socket
import logging
from os import listdir
from select import select
import protocol

SOCKET_TIMEOUT = 2


def create_server_response(client_socket: socket, request: str, symmetric_key: bytes):
    try:
        request = request.split(' ')
        command, file_name = request[0], ''.join(request[1:])

        # Request is to show valid commands
        if command in ('HELP', 'Help', 'help'):
            show_commands = protocol.create_msg(data=f"Available commands: {', '.join(list(protocol.COMMANDS)[::3])}",
                                                symmetric_key=symmetric_key)
            return show_commands

        elif command in ('LS', 'Ls', 'ls'):
            directory_content = protocol.create_msg(data=', '.join(listdir()), symmetric_key=symmetric_key)
            return directory_content

        # Request is to get a file from the server
        elif command in ('GET', 'Get', 'get'):
            encrypted_file = protocol.create_file_request(file_name, symmetric_key)

            if encrypted_file == b'File Not Found':
                not_found_msg = protocol.create_msg(data='404 File Not Found', symmetric_key=symmetric_key)
                return not_found_msg

            get_ok_message = protocol.create_msg(data='226 Transfer Complete.', symmetric_key=symmetric_key)
            return [get_ok_message, encrypted_file]

        # Request to put a file in the server
        elif command in ('PUT', 'Put', 'put'):
            valid, message = protocol.get_file_response(client_socket, symmetric_key)
            if valid:
                store_ok_message = protocol.create_msg(data='227 File Stored OK.', symmetric_key=symmetric_key)
                return store_ok_message

            else:
                error_message = protocol.create_msg(data='400 File Stored Error.', symmetric_key=symmetric_key)
                return error_message

        # Quit from the server
        elif command in ('QUIT', 'Quit', 'quit'):
            goodbye_message = protocol.create_msg(data='221 Goodbye.', symmetric_key=symmetric_key)
            return ['quit', goodbye_message]

    except ValueError:
        pass


def check_cmd(command: str):
    # Check if the command is defined in the protocol
    try:
        command = command.split(' ')[0]
    except ValueError:
        pass

    return command in protocol.COMMANDS


def main():
    logging.basicConfig(filename='Users logs.log', filemode='a', level=logging.INFO)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((protocol.ADDRESS, protocol.PORT))
    server_socket.listen()

    # Dictionary that contain the symmetric key and IP address of each socket object
    clients_symmetric_keys: dict = {tuple: bytes}

    # clients_messages is a list of sockets that needs to send messages back to the client. for more info about
    # clients_sockets list read the comment about select method.
    clients_sockets, clients_messages = [], []
    print(f'server is up and running at the IP address: {socket.gethostbyname(socket.gethostname())}, '
          f'Port: {protocol.PORT}')

    while True:
        """
         The select method take 3 argument - the first 2 are the sockets that receive or send messages, while the 
         first argument is the list of all the sockets that we expect to get messages from, that's why we add the 
         server socket with the client list because we expect a message - in this case a new connection from a new 
         socket to be received from the server socket. The second argument is a list of sockets that expected to send 
         messages, in this argument we simply use the client sockets list only cause the server socket don't need to 
         send any messages (we use the used client socket for that). The last argument is simply the timeout we wait 
         for each socket, from different test - 2 second works best for me but this can be changed easily. 
        """
        read_list, write_list, _ = select([server_socket] + clients_sockets, clients_sockets, [], SOCKET_TIMEOUT)

        """ we iterate over each socket in the read list (the list of sockets that receiving messages) and print the
            received message or receiving a new connection using the server socket """
        for current_socket in read_list:

            # if the server listened to a new socket then we create a new socket and add it to clients_socket list
            if current_socket is server_socket:
                client_socket, client_address = server_socket.accept()
                clients_sockets.append(client_socket)

                # Accept the connection, create public & private keys pair & sent the public key to the client
                public_key, private_key = protocol.init_keys()
                client_socket.send(public_key.save_pkcs1('PEM'))

                # Get the symmetric key (44 bytes long) from the user, decrypt it with private key and send OK message
                encrypted_symmetric_key = client_socket.recv(1024)
                valid, symmetric_key = protocol.decrypt_with_private_key(encrypted_symmetric_key, private_key)

                ok_message = protocol.create_msg('Connection Established!', symmetric_key)
                client_socket.send(ok_message)

                clients_symmetric_keys[client_address] = symmetric_key

                ip_address, port = client_address
                logging.info(msg=f'New client connected at the address: {ip_address}, port: {port}')

                if not valid:
                    logging.error(msg="Key exchange with the client failed")

            # if it's not a server object then a client socket have sent a message
            else:
                client_address, port = current_socket.getpeername()
                symmetric_key = clients_symmetric_keys.get((client_address, port))
                valid, user_input = protocol.get_msg(current_socket, symmetric_key=symmetric_key)

                if valid:
                    if check_cmd(user_input):
                        # Create a server response according to the client's command
                        server_response = create_server_response(current_socket, user_input, symmetric_key)

                        # Add it to the list of sending messages sockets
                        clients_messages.append((current_socket, server_response))

                    else:
                        # if the command is undefined in the protocol
                        server_response = protocol.create_msg('Invalid command, Use Help for more information!',
                                                              symmetric_key)
                        clients_messages.append((current_socket, server_response))

                else:
                    # attempt to empty the socket if an empty string was sent
                    try:
                        current_socket.recv(1024).decode()

                    #  An existing connection was forcibly closed by a client
                    except ConnectionResetError:
                        """ If a brue disconnection happened, the protocol sent the socket to the variable - data, so 
                        we remove it from the dictionary. We also need to verify if the client defined its name in order 
                        to prevent a remove of a non-existent socket. """

        """ Run through the write_list for each socket and if this socket needs to send a message, then we send it 
            and remove these socket from the write_list """
        for client in clients_messages:
            current_socket, response = client

            if current_socket in write_list:
                # User send quit, the server-response has a quit string at the first element
                if isinstance(response, list) and response[0] == 'quit':
                    client_address, port = current_socket.getpeername()
                    current_socket.send(response[1])
                    logging.info(msg=f"Closing connection with client at the address:{client_address}, port:{port}\n")
                    current_socket.close()
                    clients_sockets.remove(current_socket)
                    clients_symmetric_keys.pop((client_address, port))

                elif isinstance(response, list):
                    # send all messages the socket need to send
                    for message in response:
                        current_socket.send(message)

                else:
                    current_socket.send(response)

                # Remove the socket from client_messages lists
                clients_messages.remove(client)


if __name__ == "__main__":
    main()
