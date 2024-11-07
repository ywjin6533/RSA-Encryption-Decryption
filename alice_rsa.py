import socket
import json
import logging
import argparse
from prime import primes_in_range
from RSAKey import verify_rsa_keypair
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def send_rsa_key_request(conn):
    rsa_key_request = json.dumps({"opcode": 0, "type": "RSAKey"})
    logging.info("Preparing RSA key request to send to Bob: %s", rsa_key_request)
    conn.sendall(rsa_key_request.encode())
    logging.info("Sent RSA key request to Bob")

    data = conn.recv(4096)
    if not data:
        logging.error("No response received from Bob")
        return None

    response = json.loads(data.decode())
    logging.info("Received response from Bob: %s", response)
    verify_rsa_keypair(response)
    return response

def generate_aes_key():
    return os.urandom(32)

def encrypt_aes_key_byte_by_byte(aes_key, public_key_n, public_key_e):
    encrypted_key = [pow(byte, public_key_e, public_key_n) for byte in aes_key]
    return encrypted_key

def send_encrypted_aes_key(conn, encrypted_key):
    message = json.dumps({"opcode": 2, "encrypted_key": encrypted_key})
    logging.info("Sending encrypted AES key to Bob")
    conn.sendall(message.encode())
    logging.info("Sent encrypted AES key to Bob")

def receive_and_decrypt_message(conn, aes_key):
    data = conn.recv(4096)
    if data:
        response = json.loads(data.decode())
        if response.get("opcode") == 3:
            encrypted_message = response.get("encrypted_message")
            logging.info("Received encrypted message from Bob")

            encrypted_message_bytes = base64.b64decode(encrypted_message)
            
            backend = default_backend()
            cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=backend)
            decryptor = cipher.decryptor()
            
            decrypted_message = decryptor.update(encrypted_message_bytes) + decryptor.finalize()
            decrypted_message = decrypted_message.decode('utf-8').rstrip()
            print("Decrypted message from Bob:", decrypted_message)
        else:
            logging.warning("Unexpected message received from Bob.")
    else:
        logging.error("No encrypted message received from Bob.")

def main_routine_with_encryption(conn, response):
    verify_rsa_keypair(response)
    
    aes_key = generate_aes_key()
    logging.info("Generated AES key")

    n = response["parameter"]["p"] * response["parameter"]["q"]
    e = response["public"]
    encrypted_aes_key = encrypt_aes_key_byte_by_byte(aes_key, n, e)
    logging.info("Encrypted AES key byte-by-byte with RSA public key")

    send_encrypted_aes_key(conn, encrypted_aes_key)

    receive_and_decrypt_message(conn, aes_key)

def run(addr, port, opcode, msg_type=None):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    if opcode == 0 and msg_type == "RSAKey":
        response = send_rsa_key_request(conn)
        if response:
            main_routine_with_encryption(conn, response)
    else:
        logging.warning("Unknown opcode or message type.")
    
    conn.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    parser.add_argument("--opcode", metavar="<opcode>", help="Opcode to send", type=int, required=True)
    parser.add_argument("--type", metavar="<type>", help="Type of request (RSAKey, RSA, DH)", type=str)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.opcode, args.type)

if __name__ == "__main__":
    main()
