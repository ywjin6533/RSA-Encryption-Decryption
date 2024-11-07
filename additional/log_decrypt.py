import argparse
import logging
import json
import base64
import os
from Crypto.Cipher import AES

# AES 키 생성 함수
def create_aes_key(shared_secret):
    shared_bytes = shared_secret.to_bytes(2, byteorder="big")
    aes_key = shared_bytes * 16  # 32바이트로 확장
    return aes_key

# 복호화 함수
def decrypt_message(aes_key, encrypted_message_base64):
    encrypted_message = base64.b64decode(encrypted_message_base64)
    aes = AES.new(aes_key, AES.MODE_ECB)
    decrypted_message = aes.decrypt(encrypted_message)
    return decrypted_message.decode().strip()

# 로그 파일을 읽어 필요한 정보를 추출
def read_log_file(log_file_name):
    # 현재 파일이 위치한 디렉토리 경로를 가져옵니다.
    current_dir = os.path.dirname(__file__)
    # 파일명이 있는 파일의 전체 경로를 생성합니다.
    log_file_path = os.path.join(current_dir, log_file_name)
    
    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()
        
        # 로그에서 p, g, bob_public_key 및 암호화된 메시지 추출
        p = g = bob_public_key = None
        encrypted_messages = []
        for line in lines:
            try:
                log_entry = json.loads(line.strip())
                try:
                    if log_entry.get("opcode") == 1 and log_entry.get("type") == "DH":
                        p = log_entry["parameter"]["p"]
                        g = log_entry["parameter"]["g"]
                        bob_public_key = log_entry["public"]
                    elif log_entry.get("opcode") == 2 and log_entry.get("type") == "AES":
                        encrypted_messages.append(log_entry["encryption"])
                except:
                    pass
            except json.JSONDecodeError:
                continue
        
        return p, g, bob_public_key, encrypted_messages
    except Exception as e:
        logging.error(f"Failed to read log file: {e}")
        return None, None, None, None

# 브루트포스 공격 함수
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
            # 복호화 실패 시 무시하고 다음으로
            pass

# main 함수
def main():
    parser = argparse.ArgumentParser(description="Brute-force decrypt messages from log.")
    parser.add_argument("log_file", metavar="LOG_FILE", help="Name of the log file in the current directory")
    args = parser.parse_args()
    
    # 로그 파일에서 정보 읽기
    p, g, bob_public_key, encrypted_messages = read_log_file(args.log_file)
    
    if p and g and bob_public_key and encrypted_messages:
        logging.info("Starting brute-force attack...")
        brute_force_attack(p, bob_public_key, encrypted_messages)
    else:
        logging.error("Failed to retrieve necessary information from the log file.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
