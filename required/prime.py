def primes_in_range(lower=400, upper=500):
    """Return the list of all primes between 'lower' and 'upper'."""
    if upper < 2:
        return []

    numbers = [True] * (upper + 1)
    numbers[0:2] = [False, False]  # 0과 1은 소수가 아님

    for num in range(2, int(upper ** 0.5) + 1):
        if numbers[num]:
            for multiple in range(num * num, upper + 1, num):
                numbers[multiple] = False

    primes = [num for num in range(lower, upper + 1) if numbers[num]]
    return primes

def prime_factors(n):
    """Return the list of unique prime factors of n."""
    i = 2
    factors = set()
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            factors.add(i)
    if n > 1:
        factors.add(n)
    return factors

def is_generator(g, p):
    """Check if g is a generator for prime p using the complete test."""
    # Calculate p - 1 and its prime factors
    phi = p - 1
    factors = prime_factors(phi)
    
    # Check if g^(phi/q) % p != 1 for all prime factors q of phi
    for q in factors:
        if pow(g, phi // q, p) == 1:
            return False  # g is not a generator
    return True  # g is a generator

if __name__ == '__main__':
    primes_between_20000_and_30000 = primes_in_range(lower=20000, upper=30000)
    print(primes_between_20000_and_30000)