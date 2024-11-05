import socket
import argparse
import logging
import json

def send_rsa_key_request(conn):
    # Send RSA key request to Bob
    rsa_key_request = json.dumps({"opcode": 0, "type": "RSAKey"})
    conn.sendall(rsa_key_request.encode())
    logging.info("Sent RSA key request to Bob")

def send_rsa_encryption_request(conn):
    # Send RSA encryption/decryption request
    rsa_encryption_request = json.dumps({"opcode": 0, "type": "RSA"})
    conn.sendall(rsa_encryption_request.encode())
    logging.info("Sent RSA encryption/decryption request to Bob")

def send_dh_request(conn):
    # Send Diffie-Hellman request
    dh_request = json.dumps({"opcode": 0, "type": "DH"})
    conn.sendall(dh_request.encode())
    logging.info("Sent Diffie-Hellman request to Bob")

def send_encrypted_message(conn):
    # Send encrypted message
    encrypted_message = json.dumps({"opcode": 2, "message": "Encrypted message here"})
    conn.sendall(encrypted_message.encode())
    logging.info("Sent encrypted message to Bob")

def run(addr, port, opcode, msg_type=None):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    # Select protocol based on opcode and type
    if opcode == 0:
        if msg_type == "RSAKey":
            send_rsa_key_request(conn)
        elif msg_type == "RSA":
            send_rsa_encryption_request(conn)
        elif msg_type == "DH":
            send_dh_request(conn)
        else:
            logging.warning("Unknown type for opcode 0.")
    elif opcode == 2:
        send_encrypted_message(conn)
    else:
        logging.warning("Unknown opcode.")
    
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
