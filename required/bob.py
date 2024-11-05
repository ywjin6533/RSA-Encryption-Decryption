import socket
import threading
import argparse
import logging
import json
import select
from prime import primes_in_range

def run(addr, port, args):
    def handler(sock, stop_event):
        try:
            # Receive message from Alice
            data = sock.recv(4096)
            if data:
                received_message = data.decode()
                message = json.loads(received_message)
                
                # Process based on opcode and type
                opcode = message.get("opcode")
                msg_type = message.get("type")

                if opcode == 0:
                    if msg_type == "RSAKey":
                        logging.info("Received RSA key generation request from Alice.")
                        # RSAKey()
                    elif msg_type == "RSA":
                        logging.info("Received RSA encryption/decryption request from Alice.")
                        # RSA()
                    elif msg_type == "DH":
                        logging.info("Received Diffie-Hellman key exchange request from Alice.")
                        # DF()
                    else:
                        logging.warning("Unknown type for opcode 0.")
                elif opcode == 2:
                    if args.mod:  # -m 옵션이 True일 때만 처리
                        logging.info("Received encrypted message from Alice.")
                        # 어쩌고()
                    else:
                        logging.info("Mod is False, returning trash values.")
                        # 임의의 응답을 반환하는 로직을 추가
                elif opcode == 99 and msg_type == "exit":
                    logging.info("Received exit command. Shutting down Bob server.")
                    stop_event.set()  # Signal to stop the server
                else:
                    logging.warning("Unknown opcode.")
            else:
                logging.warning("No data received from Alice.")
        except Exception as e:
            logging.error(f"Error in connection handler: {e}")
        finally:
            sock.close()

    # Set up the server socket
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))
    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

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
    parser.add_argument("-m", "--mod", metavar="<bob's behavior>", help="if this variable is False, bob would return trash values", type=bool, default=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    return parser.parse_args()

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args)

if __name__ == "__main__":
    main()
