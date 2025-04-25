import socket
import sys
import threading

PORT = 2019

def print_received_message(message, chat_correspondent_ip):
    sys.stdout.write("\r")  # move cursor to the beginning of the line
    sys.stdout.write(chat_correspondent_ip + ": " + message + "\n")  # print the message 
    sys.stdout.write("> ")  # print the prompt again
    sys.stdout.flush()  # flush the output buffer

def handle_connection(client_socket, chat_correspondent_ip):
    while True:
        message = client_socket.recv(1024)
        if not message:
            break
        print_received_message(message.decode(), chat_correspondent_ip)
    
def get_private_ip():
    # This doesn't need to actually reach the internet
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            # Connect to a dummy address (Google DNS, won't actually send data)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"  # Fallback to localhost if anything goes wrong

def main():
    print("Server? (y/n)")
    is_server = "y" == input().lower()


    chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chat_correspondent_ip = None

    if is_server:
        chat_socket.bind((get_private_ip(), PORT))  # Replace with Client 1's IP address  
        chat_socket.listen(1)
        chat_socket, address = chat_socket.accept()
        chat_correspondent_ip = str(address)
    else:
        print("IP adress of correspondent:")
        chat_correspondent_ip = input()
        chat_socket.connect((chat_correspondent_ip, PORT))  # Replace with Client 2's IP address and port

    print(f"Connected to {chat_correspondent_ip}")

    threading.Thread(target=handle_connection, args=(chat_socket, chat_correspondent_ip)).start()

    while True:
        message = input("> ")
        chat_socket.sendall(message.encode())


if __name__ == "__main__":
    main()
