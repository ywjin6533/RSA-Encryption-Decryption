import json
import random
from math import gcd
from prime import primes_in_range

def generate_rsa_keypair():
    primes = primes_in_range(400, 500)
    p = random.choice(primes)
    q = random.choice([x for x in primes if x != p])  # p와 q가 다른지 확인
    n = p * q
    
    # 오일러 파이 함수
    phi_n = (p - 1) * (q - 1)
    
    #공개 키
    e = random.choice(range(2, phi_n))
    while gcd(e, phi_n) != 1:
        e = random.choice(range(2, phi_n))
    
    # 개인 키
    d = pow(e, -1, phi_n)
    
    # 응답 생성
    response = {
        "opcode": 0,
        "type": "RSAKey",
        "private": d,
        "public": e,
        "parameter": {"p": p, "q": q}
    }
    
    # 응답 반환
    print("Generated RSA Key Pair Response:", json.dumps(response))
    # print(json.dumps(response))  # 이부분은 테스트용, 이후에 지울 것
    return response

def verify_rsa_keypair(response):    # Alice가 Bob으로부터 받은 키를 검증
    p = response["parameter"]["p"]
    q = response["parameter"]["q"]
    e = response["public"]
    d = response["private"]

    # n과 파이 계산
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # 검증
    if (e * d) % phi_n == 1:
        print("Alice: RSA key pair is valid.")
    else:
        print("Alice: RSA key pair is invalid.")


if __name__ == "__main__":
    response = generate_rsa_keypair()
    verify_rsa_keypair(response)

