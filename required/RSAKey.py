import json
import random
from math import gcd
from prime import primes_in_range


def generate_rsa_keypair(RSA=False):
    primes = primes_in_range(400, 500)
    p = random.choice(primes)
    q = random.choice([x for x in primes if x != p])  # p와 q가 다른지 확인
    n = p * q

    # 오일러 파이 함수
    phi_n = (p - 1) * (q - 1)

    # 공개 키
    e = random.choice(range(2, phi_n))
    while gcd(e, phi_n) != 1:
        e = random.choice(range(2, phi_n))

    # 개인 키
    d = pow(e, -1, phi_n)

    # 응답 생성
    if RSA == True:
        response = {
            "opcode": 1,
            "type": "RSA",
            "public": e,
            "parameter": {"n": n},
            "secret": {"private": d}
        }
    else:
        response = {
            "opcode": 0,
            "type": "RSAKey",
            "private": d,
            "public": e,
            "parameter": {"p": p, "q": q}
        }

    # 응답 반환
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
        print(f"Alice: RSA key pair is valid. (public : {e}, private : {d})")
    else:
        print(f"Alice: RSA key pair is invalid. (public : {e}, private : {d})")


if __name__ == "__main__":
    response = generate_rsa_keypair()
    verify_rsa_keypair(response)
