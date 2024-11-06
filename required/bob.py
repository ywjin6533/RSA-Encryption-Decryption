import socket
import threading
import argparse
import logging
import json
import select
import DH
import encryption as ec
import random

def run(args):
    def handler(sock, stop_event):
        try:
            # Receive message from Alice
            while not stop_event.is_set():
                data = sock.recv(4096)
                if data:
                    received_message = data.decode()
                    message = json.loads(received_message)
                    
                    # Process based on opcode and type
                    opcode = message.get("opcode")
                    msg_type = message.get("type")

                    if opcode == 0:
                        if msg_type == "DH":
                            logging.info("Received Diffie-Hellman key exchange request from Alice.")
                            
                            # Bob's DH key setup
                            private_key, public_key, parameters = DH.dh()
                            logging.debug(f"Bob's DH private_key: {private_key}")
                            logging.debug(f"Bob's DH public_key: {public_key}")
                            logging.debug(f"DH parameters: {parameters}")
                            
                            if args.troll == True:
                                logging.info("Bob would send trash values with current setting.")
                                if random.choice([True, False]):
                                    parameters["p"] = random.randint(400, 500)  # Random value for `p`
                                    logging.info("Sent corrupted value for `p` (it would randomly be right tho)")
                                else:
                                    parameters["g"] = random.randint(2, parameters["p"] - 2)  # Random value for `g`
                                    logging.info("Sent corrupted value for `g` (it would randomly be right tho)")

                            # Send DH public key and parameters to Alice
                            response_message = {
                                "opcode": 1,
                                "type": "DH",
                                "public": public_key,
                                "parameter": parameters
                            }
                            
                            sock.sendall(json.dumps(response_message).encode())
                            logging.info("Sent DH public key and parameters to Alice.")
                        
                    elif opcode == 1:
                        if msg_type == "DH":
                            logging.info("Received Alice's DH public key.")
                            
                            # Calculate shared secret
                            alice_public_key = message["public"]
                            shared_secret = DH.compute_shared_secret(alice_public_key, private_key, parameters["p"])
                            logging.debug(f"Computed DH shared secret: {shared_secret}")
                            
                            # Create AES key
                            aes_key = DH.create_aes_key(shared_secret)
                            logging.debug(f"AES key: {aes_key.hex()}")
                            
                            # Encrypt the message with the AES key
                            encrypted_message = ec.encrypt(aes_key, args.message)
                            logging.debug(f"Encrypted message (base64): {encrypted_message}")
                            
                            # Send encrypted message to Alice
                            encrypted_message_packet = {
                                "opcode": 2,
                                "type": "AES",
                                "encryption": encrypted_message
                            }
                            sock.sendall(json.dumps(encrypted_message_packet).encode())
                            logging.info("Sent encrypted message to Alice.")
                    
                    elif opcode == 2:
                        if msg_type == "AES":
                            logging.info("Received encrypted message from Alice.")
                            
                            # Decode and decrypt the encrypted message
                            encrypted_text_base64 = message["encryption"]
                            decrypted_message = ec.decrypt(aes_key, encrypted_text_base64).decode().strip()
                            logging.info(f"Decrypted message from Alice: {decrypted_message}")
                            print(f"Decrypted message from Alice: {decrypted_message}")
                            stop_event.set()
                    
                    elif opcode == 3:
                        # Error handling: Print the error message and return to main loop
                        error_message = message.get("error", "Unknown error")
                        logging.warning(f"Received error from Alice: {error_message}")
                        print(f"Received error from Alice: {error_message}")
                        stop_event.set()
                    
                    else:
                        logging.warning("Unknown opcode.")
                else:
                    logging.warning("No data received from Alice.")
        except Exception as e:
            logging.error(f"Error in connection handler: {e}")
        finally:
            sock.close() if stop_event.is_set() else None

    # Set up the server socket
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((args.addr, args.port))
    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(args.addr, args.port))

    stop_event = threading.Event()

    # Main server loop
    while not stop_event.is_set():
        try:
            # Use select to wait for incoming connections with a timeout of 1 second
            readable, _, _ = select.select([bob], [], [], 1)
            if readable:
                conn, info = bob.accept()
                logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

                # Start a new thread to handle the connection
                conn_handle = threading.Thread(target=handler, args=(conn, stop_event))
                conn_handle.start()
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt received. Shutting down Bob server.")
            stop_event.set()
    
    bob.close()
    logging.info("Bob server has shut down.")

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="127.0.0.1")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("--troll", metavar="<bob's troll behavior>", help="Bob would send trash values", action=argparse.BooleanOptionalAction)
    parser.add_argument("-m", "--message", metavar="<bob's message>", help="bob would send this message", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    return parser.parse_args()

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args)

if __name__ == "__main__":
    main()
