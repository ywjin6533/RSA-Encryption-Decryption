import argparse
import logging
import json
import base64
import os
from Crypto.Cipher import AES

def create_aes_key(shared_secret):
    shared_bytes = shared_secret.to_bytes(2, byteorder="big")
    aes_key = shared_bytes * 16  # expand to 32 bytes
    return aes_key

def decrypt_message(aes_key, encrypted_message_base64):
    encrypted_message = base64.b64decode(encrypted_message_base64)
    aes = AES.new(aes_key, AES.MODE_ECB)
    decrypted_message = aes.decrypt(encrypted_message)
    return decrypted_message.decode().strip()

def read_log_file(log_file_name):
    current_dir = os.path.dirname(__file__)
    log_file_path = os.path.join(current_dir, log_file_name)
    
    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()
        
        # extracting p, g, bob_public_key
        p = g = bob_public_key = None
        encrypted_messages = []
        for line in lines:
            try:
                log_entry = json.loads(line.strip())
                if log_entry.get("opcode") == 1 and log_entry.get("type") == "DH":
                    try:
                        p = log_entry["parameter"]["p"]
                        g = log_entry["parameter"]["g"]
                        bob_public_key = log_entry["public"]
                    except:
                        pass
                elif log_entry.get("opcode") == 2 and log_entry.get("type") == "AES":
                    encrypted_messages.append(log_entry["encryption"])
            except json.JSONDecodeError:
                continue
        
        return p, g, bob_public_key, encrypted_messages
    except Exception as e:
        logging.error(f"Failed to read log file: {e}")
        return None, None, None, None

def brute_force_attack(p, bob_public_key, encrypted_messages):
    for private_key_guess in range(1, p):
        shared_secret_guess = pow(bob_public_key, private_key_guess, p)
        aes_key = create_aes_key(shared_secret_guess)
        
        try:
            decrypted_messages = [
                decrypt_message(aes_key, encrypted_message)
                for encrypted_message in encrypted_messages
            ]
            print(f"Private Key Guess: {private_key_guess}")
            for i, decrypted_message in enumerate(decrypted_messages, 1):
                print(f"Decrypted Message {i}: {decrypted_message}")
            print("--------------------------------------------------")
        except Exception:
            # if fail just move to another one
            pass

def main():
    parser = argparse.ArgumentParser(description="Brute-force decrypt messages from log.")
    parser.add_argument("log_file", metavar="LOG_FILE", help="Name of the log file in the current directory")
    args = parser.parse_args()
    
    p, g, bob_public_key, encrypted_messages = read_log_file(args.log_file)
    
    if p and g and bob_public_key and encrypted_messages:
        logging.info("Starting brute-force attack...")
        brute_force_attack(p, bob_public_key, encrypted_messages)
    else:
        logging.error("Failed to retrieve necessary information from the log file.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
