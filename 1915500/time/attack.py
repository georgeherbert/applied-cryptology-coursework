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

def mpz_size(n):
    return math.ceil(math.log(n, B))

def mont_omega(n):
    t = 1
    for _ in range(W):
        t = (pow(t, 2, B) * n) % B
    return -t % B
    
def mont_rho_sq(n, l_n):
    return pow(2, 2 * l_n * W, n)

def attack():
    n, e = get_attack_params()
    l_n = mpz_size(n)
    omega = mont_omega(n)
    rho_sq = mont_rho_sq(n, l_n)

    print(omega)
    print("")
    print(rho_sq)

    # random_messages = [random.randint(0, n - 1) for _ in range(50)]
    # print(random_messages)

if __name__ == "__main__":
    attack()