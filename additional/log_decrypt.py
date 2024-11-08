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

# AES 복호화 함수


def decrypt_message(aes_key, encrypted_message_base64):
    encrypted_message = base64.b64decode(encrypted_message_base64)
    aes = AES.new(aes_key, AES.MODE_ECB)
    decrypted_message = aes.decrypt(encrypted_message)
    return decrypted_message.decode().strip()

# 유클리드 알고리즘을 이용한 최대공약수 계산


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# 확장 유클리드 알고리즘을 이용한 모듈러 역수 계산


def mod_inverse(e, phi_n):
    t, new_t = 0, 1
    r, new_r = phi_n, e
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError("e has no modular inverse under phi_n")
    if t < 0:
        t = t + phi_n
    return t

# RSA 키 생성 함수 (d 계산)


def calculate_private_key(e, p, q):
    phi_n = (p - 1) * (q - 1)
    d = mod_inverse(e, phi_n)
    return d

# RSA 복호화 함수


def rsa_decrypt(d, n, encrypted_data):
    return [pow(c, d, n) for c in encrypted_data]

# DH 공격 함수


def brute_force_attack_dh(p, bob_public_key, encrypted_messages):
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

# RSA 공격 함수


def brute_force_attack_rsa(e, n, encrypted_key, encrypted_messages):
    # n을 소인수 분해하여 p와 q를 찾습니다.
    p, q = find_factors(n)
    if not p or not q:
        logging.error("Failed to factorize n into p and q.")
        return

    logging.debug(f"Factors of n: p = {p}, q = {q}")

    # RSA private key (d) 계산
    d = calculate_private_key(e, p, q)
    logging.debug(f"Calculated private key d = {d}")

    # 암호화된 AES 키 복호화
    decrypted_aes_key_parts = rsa_decrypt(d, n, encrypted_key)
    aes_key = bytes(decrypted_aes_key_parts)
    logging.debug(f"aes_key: {aes_key}")

    # AES 메시지 복호화
    for encrypted_message in encrypted_messages:
        decrypted_message = decrypt_message(aes_key, encrypted_message)
        print("Decrypted Message:", decrypted_message)

# n을 소인수 분해하여 p와 q 찾기


def find_factors(n):
    primes = primes_in_range(400, 500)
    for p in primes:
        if n % p == 0:
            q = n // p
            if q in primes:
                return p, q
    return None, None

# 주어진 범위에서 p와 q를 찾기 위해 소수 목록 생성


def primes_in_range(start, end):
    primes = []
    for num in range(start, end + 1):
        if all(num % i != 0 for i in range(2, int(num ** 0.5) + 1)):
            primes.append(num)
    return primes

# 로그 파일을 읽어 필요한 정보를 추출


def read_log_file(log_file_name):
    # 현재 파일이 위치한 디렉토리 경로를 가져옵니다.
    current_dir = os.path.dirname(__file__)
    log_file_path = os.path.join(current_dir, log_file_name)

    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()

        # 로그에서 필요한 정보를 추출
        mode = None
        p = g = bob_public_key = e = n = None
        encrypted_key = []
        encrypted_messages = []
        for line in lines:
            try:
                log_entry = json.loads(line.strip())
                opcode, msg_type = log_entry.get(
                    "opcode"), log_entry.get("type")

                if opcode == 1 and msg_type == "DH":
                    mode = "DH"
                    try:
                        p = log_entry["parameter"]["p"]
                        g = log_entry["parameter"]["g"]
                        bob_public_key = log_entry["public"]
                    except:
                        pass
                elif opcode == 1 and msg_type == "RSA":
                    mode = "RSA"
                    e = log_entry["public"]
                    n = log_entry["parameter"]["n"]
                elif opcode == 2 and msg_type == "RSA":
                    encrypted_key = log_entry["encrypted_key"]
                elif opcode == 2 and msg_type == "AES":
                    encrypted_messages.append(log_entry["encryption"])
            except json.JSONDecodeError:
                continue

        return mode, p, g, bob_public_key, e, n, encrypted_key, encrypted_messages
    except Exception as e:
        logging.error(f"Failed to read log file: {e}")
        return None, None, None, None, None, None, None, None

# main 함수


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt DH or RSA encrypted messages based on log type.")
    parser.add_argument("log_file", metavar="<LOG_FILE>",
                        help="Name of the log file in the current directory")
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>",
                        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=args.log)

    # 로그 파일에서 정보 읽기
    mode, p, g, bob_public_key, e, n, encrypted_key, encrypted_messages = read_log_file(
        args.log_file)

    if mode == "DH" and p and g and bob_public_key and encrypted_messages:
        logging.info("Starting DH brute-force attack...")
        brute_force_attack_dh(p, bob_public_key, encrypted_messages)
    elif mode == "RSA" and e and n and encrypted_key and encrypted_messages:
        logging.info("Starting RSA decryption...")
        brute_force_attack_rsa(e, n, encrypted_key, encrypted_messages)
    else:
        logging.error(
            "Failed to retrieve necessary information from the log file.")


if __name__ == "__main__":
    main()
