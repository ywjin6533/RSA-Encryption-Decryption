def primes_in_range(lower=400, upper=500):
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

if __name__ == '__main__':
    primes_between_20000_and_30000 = primes_in_range(lower=20000, upper=30000)
    print(primes_between_20000_and_30000)