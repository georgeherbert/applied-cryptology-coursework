import sys
import subprocess
import random
import math
import statistics

TARGET = subprocess.Popen(
    args = f"./{sys.argv[1]}",
    stdin = subprocess.PIPE,
    stdout = subprocess.PIPE
)
TARGET_IN = TARGET.stdin
TARGET_OUT = TARGET.stdout

W = 64 # Word length
B = 2 ** W # Base

def get_attack_params():
    with open(sys.argv[2], "r") as config:
        return [int(config.readline().strip(), 16) for _ in range(2)]

def mont_omega(n):
    t = 1
    for _ in range(W):
        t = (pow(t, 2, B) * n) % B
    return -t % B

def interact(ciphertext):
    TARGET_IN.write(f"{ciphertext:x}\n".encode())
    TARGET_IN.flush()
    time = int(TARGET_OUT.readline().strip())
    message = int(TARGET_OUT.readline().strip(), 16)
    return time, message

def mpz_getlimbn(op, n):
    return op >> (n * W) & (2 ** W - 1)

def mont_mul(x, y, l_n, omega, n):
    r = 0
    subtraction = False
    x_0 = mpz_getlimbn(x, 0)
    for i in range(0, l_n):
        r_0 = mpz_getlimbn(r, 0)
        y_i = mpz_getlimbn(y, i)
        u_i = ((r_0 + y_i * x_0) * omega) % B
        r = (r + y_i * x + u_i * n) >> W
    if r >= n:
        r -= n
        subtraction = True
    return r, subtraction

def square_and_multiply_init(rho_sq, l_n, omega, n, x):
    t = mont_mul(1, rho_sq, l_n, omega, n)[0]
    t = mont_mul(t, t, l_n, omega, n)[0]
    t = mont_mul(t, x, l_n, omega, n)[0] # First bit is 1
    t = mont_mul(t, t, l_n, omega, n)[0]
    return t

def square_and_multiply_next(d_i, t, x, l_n, omega, n):
    if d_i:
        t = mont_mul(t, x, l_n, omega, n)[0]
    t = mont_mul(t, t, l_n, omega, n)
    return t

def test(d, e, n):
    m = 0x123456789ABCDEF
    c = pow(m, e, n)
    d_zero = d << 1
    d_one = d_zero + 1
    if pow(c, d_zero, n) == m:
        return d_zero
    elif pow(c, d_one, n) == m:
        return d_one
    else:
        return False

def attack():
    n, e = get_attack_params()
    l_n = math.ceil(math.log(n, B))
    omega = mont_omega(n)
    rho_sq = pow(2, 2 * l_n * W, n)
    print(f"n: {n}\n\ne: {e}\n\nl_n: {l_n}\n\nomega: {omega}\n\nrho_sq: {rho_sq}\n\n")

    ciphertext_samples = [random.randrange(0, n) for _ in range(5000)]
    ciphertext_times = [interact(ciphertext)[0] for ciphertext in ciphertext_samples]
    ciphertext_monts = [mont_mul(c, rho_sq, l_n, omega, n)[0] for c in ciphertext_samples] ## IMPORTANT!

    d = 0x1

    m_temps = [square_and_multiply_init(rho_sq, l_n, omega, n, x) for x in ciphertext_monts]

    while True:
        ciphertext_mont_bit_one = [square_and_multiply_next(True, m_temp, x, l_n, omega, n) for m_temp, x in zip(m_temps, ciphertext_monts)]
        ciphertext_mont_bit_zero = [square_and_multiply_next(False, m_temp, x, l_n, omega, n) for m_temp, x in zip(m_temps, ciphertext_monts)] 

        M_1 = statistics.mean([ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_one) if reduction])
        M_2 = statistics.mean([ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_one) if not reduction])
        M_3 = statistics.mean([ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_zero) if reduction])
        M_4 = statistics.mean([ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_zero) if not reduction])

        print(abs(M_1 - M_2))
        print(abs(M_3 - M_4))

        diff = abs(M_1 - M_2) - abs(M_3 - M_4)
        d <<= 1
        if diff >= 0:
            d += 1
            m_temps = [i[0] for i in ciphertext_mont_bit_one]
        elif diff < 0:
            d += 0
            m_temps = [i[0] for i in ciphertext_mont_bit_zero]

        d_test = test(d, e, n)
        if d_test:
            break

        print(f"d: {d:b}\n")

    print(f"d: {d_test:b}\n")
    print(f"d: {d_test:x}\n")

if __name__ == "__main__":
    attack()