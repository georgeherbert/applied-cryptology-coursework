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

def mpz_getlimbn(op, n):
    return op >> (n * W) & (2 ** W - 1)

def montmul(x, y, l_n, omega, n):
    r = 0
    subtraction = False
    for i in range(0, l_n):
        r_0 = mpz_getlimbn(r, 0)
        y_i = mpz_getlimbn(y, i)
        x_0 = mpz_getlimbn(x, i)
        u_i = ((r_0 + y_i * x_0) * omega) % B
        r = (r + y_i + x + u_i * n) >> W
    if r >= n:
        r -= n
        subtraction = True
    return r, subtraction

def attack():
    n, e = get_attack_params()
    l_n = mpz_size(n)
    omega = mont_omega(n)
    rho_sq = mont_rho_sq(n, l_n)

    print(omega)
    print("")
    print(rho_sq)

    # ciphertext_samples = [random.randrange(0, n) for _ in range(100)]

if __name__ == "__main__":
    attack()