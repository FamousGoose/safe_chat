import socket
import os

PORT = 8080

def generate_aes_key():
    # Generate a random 256-bit key
    key = os.urandom(32)

    return key

def generate_aes_key_pair():
    # Generate a random 256-bit key
    private_key = generate_aes_key()
    public_key = generate_aes_key()

    # Return the key as the "key pair"
    return private_key, public_key

def listen_on_port(port):
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    sock.bind(('0.0.0.0', port))

    # Listen for incoming connections
    sock.listen(1)

    # print(f"Listening on port {port}...") TODO maybe log

    while True:
        # Accept incoming connections
        conn, addr = sock.accept()
        # print(f"Connection from {addr}") TODO maybe log

        # Handle the incoming data
        data = conn.recv(1024)
        # print(f"Received data: {data}") TODO maybe log

        # Close the connection
        conn.close()

def send_data(ip_address, port, data):
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while True:
        try:
            # Connect to the IP address and port
            sock.connect((ip_address, port))
            break
        except ConnectionRefusedError:
            print("Connection refused")

    # Send the data
    sock.sendall(data.encode())

    # Close the socket
    sock.close()

def wait_for_public_key(chat_socket):
    while True:
            # Accept incoming connections
            conn, addr = chat_socket.accept()
            # print(f"Connection from {addr}") TODO maybe log

            # Handle the incoming data
            data = conn.recv(1024)
            if data[0:8].decode("utf-8") == "pub_key:":
                return data[8:]

# Send the string "Hello, world!" to 192.168.1.100 on port 8080
# send_data("192.168.1.220", 8080, "Hello, world!")

# Listen on port 8080
# listen_on_port(PORT)

def main():
    # Create a socket object
    chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    chat_socket.bind(('0.0.0.0', PORT))

    # Listen for incoming connections
    chat_socket.listen(1)

    RECEIVER_IP = "192.168.1.220" #TODO Change this to allow multiple chats
    private_key, public_key = generate_aes_key_pair()
    print("Sending public key to " + RECEIVER_IP)
    send_data(RECEIVER_IP, 8080, "pub_key:" + str(public_key))
    print("Waiting for public key from " + RECEIVER_IP)
    public_key = wait_for_public_key(chat_socket)
    print("Received public key: " + str(public_key))
    print("Connected to " + RECEIVER_IP)
    # print("Sending public key to " + RECEIVER_IP)
    # send_data(RECEIVER_IP, 8080, "pub_key:" + str(public_key))


main()
