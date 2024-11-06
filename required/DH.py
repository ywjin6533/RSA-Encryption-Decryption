import random
from prime import primes_in_range, is_generator

def generate_dh_keypair(p, g):
    """Generate Alice's DH private and public key"""
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_secret(others_public_key, my_private_key, p):
    """Compute the DH shared secret"""
    shared_secret = pow(others_public_key, my_private_key, p)
    return shared_secret

def create_aes_key(shared_secret):
    """Convert shared_secret to bytes and repeat to make a 32-byte AES key"""
    shared_bytes = shared_secret.to_bytes(2, byteorder="big")
    aes_key = shared_bytes * 16  # Repeat to create a 32-byte key
    return aes_key


def dh():
    # Generate DH parameters
    primes = primes_in_range()  # List of primes between 400 and 500
    p = random.choice(primes)  # Randomly select a prime p from the list
    
    # Find a generator g for prime p
    g = random.randint(2, p - 2)
    while not is_generator(g, p):  # Repeat until a valid generator is found
        g = random.randint(2, p - 2)

    # Generate Bob's private and public keys
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)

    # Return public key, private key, and parameters
    return private_key, public_key, {"p": p, "g": g}