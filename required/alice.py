import socket
import argparse
import logging
import json
from prime import primes_in_range, is_generator # import useful functions for primes related actions we made
import DH # import useful modules for Diffie-Hellman protocol we made
import encryption as ec # import encryption module we made

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
    
def handle_dh_exchange(conn, data, alice_message):    
    # Parse DH parameters from Bob's message
    message = json.loads(data.decode())
    p = message["parameter"]["p"]
    g = message["parameter"]["g"]
    bob_public = message["public"]
    
    
    def validate_parameters(conn, p, g):
        """Check if p is a prime number and g is a generator for p"""
        primes = primes_in_range()
    
        # Check if p is a prime number
        if p not in primes:
            error_message = {
                "opcode": 3,
                "error": "incorrect prime number"
            }
            try:
                conn.sendall(json.dumps(error_message).encode())
                logging.info("Sent error to Bob: incorrect prime number.")
            except Exception as e:
                logging.error(f"Failed to send error message to Bob: {e}")
            return False

        # Check if g is a generator for p
        if not is_generator(g, p):
            error_message = {
                "opcode": 3,
                "error": "incorrect generator"
            }
            try:
                conn.sendall(json.dumps(error_message).encode())
                logging.info("Sent error to Bob: incorrect generator.")
            except Exception as e:
                logging.error(f"Failed to send error message to Bob: {e}")
            return False

        return True
    
    
    # Validate p and g
    if not validate_parameters(conn, p, g):
        logging.error("DH parameters validation failed.")
        return
    
    # Generate Alice's DH key pair
    private_key, alice_public = DH.generate_dh_keypair(p, g)
    logging.debug(f"Alice's DH private key: {private_key}")
    logging.debug(f"Alice's DH public key: {alice_public}")

    # Compute the shared secret
    shared_secret = DH.compute_shared_secret(bob_public, private_key, p)
    logging.debug(f"Computed DH shared secret: {shared_secret}")

    # Create the AES key
    aes_key = DH.create_aes_key(shared_secret)
    logging.debug(f"AES key: {aes_key.hex()}")

    # Send Alice's DH public key to Bob
    response_message = {
        "opcode": 1,
        "type": "DH",
        "public": alice_public
    }
    
    try:
        conn.sendall(json.dumps(response_message).encode())
        logging.info("Sent Alice's DH public key to Bob.")
    except Exception as e:
        logging.error(f"Failed to send DH public key to Bob: {e}")
    
    # Wait for the encrypted message from Bob
    encrypted_data = conn.recv(4096)
    if encrypted_data:
        encrypted_message = json.loads(encrypted_data.decode())
        if encrypted_message["opcode"] == 2 and encrypted_message["type"] == "AES":
            encrypted_text_base64 = encrypted_message["encryption"]
            logging.info("Received encrypted message from Bob.")
            
            # Decrypt the message from Bob using AES key
            decrypted_message = ec.decrypt(aes_key, encrypted_text_base64).decode().strip()
            logging.info(f"Decrypted message from Bob: {decrypted_message}")
            print(f"Decrypted message from Bob: {decrypted_message}")

            # Encrypt Alice's response message with AES
            encrypted_response = ec.encrypt(aes_key, alice_message)
            response_packet = {
                "opcode": 2,
                "type": "AES",
                "encryption": encrypted_response
            }

            # Send encrypted response to Bob
            try:
                conn.sendall(json.dumps(response_packet).encode())
                logging.info("Sent encrypted response to Bob.")
            except Exception as e:
                logging.error(f"Failed to send encrypted response to Bob: {e}")
        else:
            logging.critical("This should not happen!!!")
            error_message = {
                "opcode": 3,
                "Unknown error": "This is impossible"
            }
            conn.sendall(json.dumps(error_message).encode())
                
    else:
        logging.error("No encrypted message received from Bob for AES exchange.")
        error_message = {
            "opcode": 3,
            "error": "No encrypted message received from Bob for AES exchange."
        }
        conn.sendall(json.dumps(error_message).encode())

def send_encrypted_message(conn):
    # Send encrypted message
    encrypted_message = json.dumps({"opcode": 2, "message": "Encrypted message here"})
    conn.sendall(encrypted_message.encode())
    logging.info("Sent encrypted message to Bob")

def run(args):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((args.addr, args.port))
    logging.info("Alice is connected to {}:{}".format(args.addr, args.port))
    opcode = 0
    
    # Select protocol based on opcode and type
    if args.type == "RSAKey":
        send_rsa_key_request(conn)
    elif args.type == "RSA":
        send_rsa_encryption_request(conn)
    elif args.type == "DH":
        send_dh_request(conn)
        
        # Wait for Bob's response with DH parameters
        data = conn.recv(4096)
        if data:
            logging.info("data received from Bob for DH exchange.")
            handle_dh_exchange(conn, data, args.message)
        else:
            logging.error("No data received from Bob for DH exchange.")
    else:
        logging.warning("Unknown type of request by Alice")
    
    conn.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<alice's address>", help="Alice's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<alice's port>", help="Alice's port", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<alice's message>", help="Alice would send this message if needed", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    parser.add_argument("--type", metavar="<type>", help="Type of request (RSAKey, RSA, DH)", type=str)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args)

if __name__ == "__main__":
    main()
