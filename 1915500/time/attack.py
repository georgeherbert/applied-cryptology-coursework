import sys
import subprocess
import random
import math

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

def mpz_size(op):
    return math.ceil(math.log(op, B))

def mont_omega(n):
    t = 1
    for _ in range(W):
        t = (pow(t, 2, B) * n) % B
    return -t % B
    
def mont_rho_sq(n, l_n):
    return pow(2, 2 * l_n * W, n)

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

def mont_exp(rho_sq, n, x, y, l_n, omega):
    t = mont_mul(1, rho_sq, l_n, omega, n)[0]
    x = mont_mul(x, rho_sq, l_n, omega, n)[0]
    y_size = int(math.log(y, 2))
    for i in range(y_size, -1, -1):
        t = mont_mul(t, t, l_n, omega, n)[0]
        if (y >> i) & 1:
            t = mont_mul(t, x, l_n, omega, n)[0]
    return mont_mul(t, 1, l_n, omega, n)[0]

def square_and_multiply_init(rho_sq, l_n, omega, n, x):
    # Conversion of values at the start of mont_exp
    t = mont_mul(1, rho_sq, l_n, omega, n)[0]
    # First loop round since assuming first bit is 1
    t = mont_mul(t, t, l_n, omega, n)[0]
    t = mont_mul(t, x, l_n, omega, n)[0] # Assumes first bit is 1
    # Performs last calculation before checking the bit of the second iteration
    t = mont_mul(t, t, l_n, omega, n)[0]
    return t

def square_and_multiply_next(d_i, t, x, l_n, omega, n):
    if d_i:
        t = mont_mul(t, x, l_n, omega, n)[0]
    t = mont_mul(t, t, l_n, omega, n)
    return t

def attack():
    n, e = get_attack_params()
    l_n = mpz_size(n)
    omega = mont_omega(n)
    rho_sq = mont_rho_sq(n, l_n)
    print(f"n: {n}\n\ne: {e}\n\nl_n: {l_n}\n\nomega: {omega}\n\nrho_sq: {rho_sq}\n\n")

    ciphertext_samples = [random.randrange(0, n) for _ in range(50000)]
    ciphertext_times = [interact(ciphertext)[0] for ciphertext in ciphertext_samples]
    ciphertext_monts = [mont_mul(c, rho_sq, l_n, omega, n)[0] for c in ciphertext_samples] ## IMPORTANT!

    m_temps = [square_and_multiply_init(rho_sq, l_n, omega, n, x) for x in ciphertext_monts]
    
    ciphertext_mont_bit_one = [square_and_multiply_next(True, m_temp, x, l_n, omega, n) for m_temp, x in zip(m_temps, ciphertext_monts)]
    ciphertext_mont_bit_zero = [square_and_multiply_next(False, m_temp, x, l_n, omega, n) for m_temp, x in zip(m_temps, ciphertext_monts)] 

    M_1 = [ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_one) if reduction]
    M_2 = [ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_one) if not reduction]
    M_3 = [ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_zero) if reduction]
    M_4 = [ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_zero) if not reduction]

    M_1_mean = sum(M_1) / len(M_1)
    M_2_mean = sum(M_2) / len(M_2)
    M_3_mean = sum(M_3) / len(M_3)
    M_4_mean = sum(M_4) / len(M_4)

    print(abs(M_1_mean - M_2_mean))
    print(abs(M_3_mean - M_4_mean))

if __name__ == "__main__":
    attack()