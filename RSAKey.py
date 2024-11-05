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
    
    # 공개 키, 서로소 아니면 다시
    e = 65537 #이거 맞나?
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
    print(json.dumps(response))  # 이부분은 테스트용, 이후에 지울 것
    return response

if __name__ == '__main__':
    generate_rsa_keypair()

