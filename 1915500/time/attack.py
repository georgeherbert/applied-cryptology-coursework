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

TEST_MESSAGE = 0x123456789abcdef
INITIAL_SAMPLES = 5000

def get_attack_params():
    with open(sys.argv[2], "r") as config:
        return [int(config.readline().strip(), 16) for _ in range(2)]

def mont_omega(n):
    t = 1
    for _ in range(W):
        t = (pow(t, 2, B) * n) % B
    return -t % B

def calc_montgomery_params(n):
    l_n = math.ceil(math.log(n, B))
    omega = mont_omega(n)
    rho_sq = pow(2, 2 * l_n * W, n)
    return l_n, omega, rho_sq

def gen_ciphertext_samples_times(n, num_samples):
    ciphertext_samples = [random.randrange(0, n) for _ in range(num_samples)]
    ciphertext_times = [interact(ciphertext)[0] for ciphertext in ciphertext_samples]
    return ciphertext_samples, ciphertext_times

def interact(ciphertext):
    TARGET_IN.write(f"{ciphertext:x}\n".encode())
    TARGET_IN.flush()
    time = int(TARGET_OUT.readline().strip())
    message = int(TARGET_OUT.readline().strip(), 16)
    return time, message

def mont_mul(x, y, l_n, omega, n):
    x_0 = x & (B - 1)
    r = 0
    for i in range(l_n):
        r_0 = r & (B - 1)
        y_i = y >> (i * W) & (B - 1)
        u_i = ((r_0 + y_i * x_0) * omega) % B
        r = (r + y_i * x + u_i * n) >> W
    reduction = r >= n
    return r - n if reduction else r, reduction

def mont_exp_init(rho_sq, l_n, omega, n, x):
    t = mont_mul(1, rho_sq, l_n, omega, n)[0]
    t = mont_mul(t, t, l_n, omega, n)[0]
    t = mont_mul(t, x, l_n, omega, n)[0]
    t = mont_mul(t, t, l_n, omega, n)[0]
    return t

def mont_exp_next(d_i, t, x, l_n, omega, n):
    if d_i:
        t = mont_mul(t, x, l_n, omega, n)[0]
    t = mont_mul(t, t, l_n, omega, n)
    return t

def test_d(d, e, n):
    print(f"d (base 2): {d:b}")
    c = pow(TEST_MESSAGE, e, n)
    d *= 2
    return pow(c, d, n) == TEST_MESSAGE or pow(c, d + 1, n) == TEST_MESSAGE

def calc_final_bit(d, e, n):
    c = pow(TEST_MESSAGE, e, n)
    return pow(c, d * 2 + 1, n) == TEST_MESSAGE

def calculate_d(n, rho_sq, l_n, omega, e):
    ciphertext_samples, ciphertext_times = gen_ciphertext_samples_times(n, INITIAL_SAMPLES)
    interactions = INITIAL_SAMPLES
    ciphertext_monts = [mont_mul(c, rho_sq, l_n, omega, n)[0] for c in ciphertext_samples]
    m_temps = [mont_exp_init(rho_sq, l_n, omega, n, x) for x in ciphertext_monts]

    d = 0x1
    while not test_d(d, e, n):
        ciphertext_mont_bit_one = [mont_exp_next(True, m_temp, x, l_n, omega, n) for m_temp, x in zip(m_temps, ciphertext_monts)]
        ciphertext_mont_bit_zero = [mont_exp_next(False, m_temp, x, l_n, omega, n) for m_temp, x in zip(m_temps, ciphertext_monts)] 
        M_1 = statistics.mean([ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_one) if reduction])
        M_2 = statistics.mean([ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_one) if not reduction])
        M_3 = statistics.mean([ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_zero) if reduction])
        M_4 = statistics.mean([ciphertext_times[i] for i, (_, reduction) in enumerate(ciphertext_mont_bit_zero) if not reduction])
        # print(abs(M_1 - M_2))
        # print(abs(M_3 - M_4))

        diff = abs(M_1 - M_2) - abs(M_3 - M_4)
        d *= 2
        if diff >= 0:
            m_temps = [i[0] for i in ciphertext_mont_bit_one]
            d += 1
        elif diff < 0:
            m_temps = [i[0] for i in ciphertext_mont_bit_zero]

    d = d * 2 + calc_final_bit(d, e, n)
    return d, interactions

def attack():
    n, e = get_attack_params()
    l_n, omega, rho_sq = calc_montgomery_params(n)
    print(f"n (base 10): {n}\n\ne (base 10): {e}\n\nl_n (base 10): {l_n}\n\nomega (base 10): {omega}\n\nrho_sq (base 10): {rho_sq}\n")

    d, interactions = calculate_d(n, rho_sq, l_n, omega, e)

    print(f"d (base 2): {d:b}\n")
    print(f"d (base 16): {d:x}\n")
    
    print(d)
    print(interactions)

if __name__ == "__main__":
    attack()