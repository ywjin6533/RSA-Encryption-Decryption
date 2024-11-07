import socket
import threading
import argparse
import logging
import json
import select
import base64
from RSAKey import generate_rsa_keypair

def decrypt_aes_key(encrypted_key, private_key_d, n):
    decrypted_key = bytes([pow(byte, private_key_d, n) for byte in encrypted_key])
    return decrypted_key

def aes_encrypt(message, key):
    # ECB 모드를 직접 구현한 AES 암호화
    block_size = 16
    padded_message = message + ' ' * (block_size - len(message) % block_size)
    encrypted = b''

    for i in range(0, len(padded_message), block_size):
        block = padded_message[i:i+block_size]
        encrypted_block = int.from_bytes(block.encode(), 'big') ^ int.from_bytes(key[:block_size], 'big')
        encrypted += encrypted_block.to_bytes(block_size, 'big')

    return base64.b64encode(encrypted).decode()

def handler(sock, stop_event):
    try:
        data = sock.recv(4096)
        if not data:
            logging.warning("No data received from Alice. Connection may be closed.")
            return

        received_message = data.decode()
        logging.info("Raw data received from Alice: %s", received_message)
        message = json.loads(received_message)
        
        if message.get("opcode") == 0 and message.get("type") == "RSAKey":
            logging.info("Received RSA key generation request from Alice.")
            rsa_keys = generate_rsa_keypair()
            response_json = json.dumps(rsa_keys)
            sock.sendall(response_json.encode())
            logging.info("Sent RSA public key to Alice.")
        
        data = sock.recv(4096)
        if data:
            received_message = data.decode()
            message = json.loads(received_message)
            if message.get("opcode") == 2:
                logging.info("Received encrypted AES key from Alice.")
                
                encrypted_key = message.get("encrypted_key")
                private_key_d = rsa_keys["private"]
                n = rsa_keys["parameter"]["p"] * rsa_keys["parameter"]["q"]

                aes_key = decrypt_aes_key(encrypted_key, private_key_d, n)
                encrypted_message = aes_encrypt("hello", aes_key)
                response = json.dumps({"opcode": 3, "encrypted_message": encrypted_message})
                sock.sendall(response.encode())

                logging.info("Sent encrypted message to Alice.")
                
    except Exception as e:
        logging.error(f"Error in connection handler: {e}")
    finally:
        sock.close()

def run(addr, port):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))
    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    stop_event = threading.Event()

    while not stop_event.is_set():
        try:
            readable, _, _ = select.select([bob], [], [], 1)
            if readable:
                conn, info = bob.accept()
                logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))
                conn_handle = threading.Thread(target=handler, args=(conn, stop_event))
                conn_handle.start()
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt received. Shutting down Bob server.")
            stop_event.set()
    
    bob.close()
    logging.info("Bob server has shut down.")

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    run(args.addr, args.port)

if __name__ == "__main__":
    main()
