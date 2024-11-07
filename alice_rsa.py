import socket
import json
import logging
import argparse
from prime import primes_in_range
from RSAKey import verify_rsa_keypair
import os

def send_rsa_key_request(conn):
    # Send RSA key request to Bob
    rsa_key_request = json.dumps({"opcode": 0, "type": "RSAKey"})
    conn.sendall(rsa_key_request.encode())
    logging.info("Sent RSA key request to Bob")

    # Receive response from Bob
    data = conn.recv(4096)
    if not data:
        logging.error("No response received from Bob")
        return None

    response = json.loads(data.decode())
    logging.info("Received response from Bob: %s", response)
    verify_rsa_keypair(response)  # 검증
    return response  # 공개키 정보를 반환

def generate_aes_key():
    # 256-bit (32-byte) AES 대칭키 생성
    return os.urandom(32)

def encrypt_aes_key_byte_by_byte(aes_key, public_key_n, public_key_e):
    # RSA 공개키를 사용해 AES 대칭키의 각 바이트를 암호화
    encrypted_key = []
    for byte in aes_key:
        encrypted_byte = pow(byte, public_key_e, public_key_n)
        encrypted_key.append(encrypted_byte)
    return encrypted_key

def send_encrypted_aes_key(conn, encrypted_key):
    # 암호화된 AES 키를 JSON 형식으로 전송
    message = json.dumps({"opcode": 2, "encrypted_key": encrypted_key})
    conn.sendall(message.encode())
    logging.info("Sent encrypted AES key to Bob")

def main_routine_with_encryption(conn, response):
    # RSA 공개키 검증
    verify_rsa_keypair(response)
    
    # AES 대칭키 생성
    aes_key = generate_aes_key()
    logging.info("Generated AES key")

    # RSA 공개키로 AES 대칭키 암호화
    n = response["parameter"]["p"] * response["parameter"]["q"]
    e = response["public"]
    encrypted_aes_key = encrypt_aes_key_byte_by_byte(aes_key, n, e)
    logging.info("Encrypted AES key byte-by-byte with RSA public key")

    # 암호화된 대칭키를 Bob에게 전송
    send_encrypted_aes_key(conn, encrypted_aes_key)

def run(addr, port, opcode, msg_type=None):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    # RSA 키 요청 보내기
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
