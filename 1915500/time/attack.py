import sys
import subprocess
import random
import math
from tkinter import N

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
    message = int(TARGET_OUT.readline().strip())
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

def attack():
    n, e = get_attack_params()
    l_n = mpz_size(n)
    omega = mont_omega(n)
    rho_sq = mont_rho_sq(n, l_n)

    # ciphertext_samples = [random.randrange(0, n) for _ in range(1000)]


    print(mont_exp(rho_sq, n, 1203, 300, l_n, omega))



if __name__ == "__main__":
    attack()