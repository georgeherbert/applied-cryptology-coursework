import sys
import subprocess
import math
from decimal import Decimal, getcontext, ROUND_CEILING, ROUND_FLOOR

TARGET = subprocess.Popen(
    args = f"./{sys.argv[1]}",
    stdin = subprocess.PIPE,
    stdout = subprocess.PIPE
)
TARGET_IN = TARGET.stdin
TARGET_OUT = TARGET.stdout

def get_attack_params():
    with open(sys.argv[2], "r") as config:
        return [config.readline().strip() for _ in range(4)]

def int_to_pretty_hex(value_int, k):
    return f"{k:x}:{value_int:0{k * 2}x}"

def interact(l, c):
    TARGET_IN.write(f"{l}\n".encode())
    TARGET_IN.write(f"{c}\n".encode())
    TARGET_IN.flush()
    return int(TARGET_OUT.readline().strip())

def send_to_oracle(f, e, n, c, k, l):
    # p1 = pow(f, e, n)
    # p2 = (p1 * c) % n
    value = (pow(f, e, n) * c) % n
    value_pretty = int_to_pretty_hex(value, k)
    return interact(l, value_pretty)

def step_1(e, n, c, k, l):
    f_1 = 2
    while send_to_oracle(f_1, e, n, c, k, l) != 2:
        f_1 *= 2
    return f_1

def step_2(f_1, n, B, e, c, k, l):
    f_2 = int(math.floor((n + B) / B) * (f_1 / 2))
    while send_to_oracle(f_2, e, n, c, k, l) != 1:
        f_2 += int(f_1 / 2)
    return f_2

def step_3(f_2, n, B, e, c, k, l):
    getcontext().prec = 500

    m_min = Decimal(n / f_2).to_integral_value(rounding = ROUND_CEILING)
    m_max = Decimal((n + B) / f_2).to_integral_value(rounding = ROUND_FLOOR)
    
    while True:
        f_tmp = Decimal((2 * B) / (m_max - m_min)).to_integral_value(rounding = ROUND_FLOOR)
        i = Decimal((f_tmp * m_min) / n).to_integral_value(rounding = ROUND_FLOOR)
        f_3 = Decimal((i * n) / m_min).to_integral_value(rounding = ROUND_CEILING)
        response = send_to_oracle(int(f_3), e, n, c, k, l)
        if response == 2:
            m_min = Decimal((i * n + B) / f_3).to_integral_value(rounding = ROUND_CEILING)
        elif response == 1:
            m_max = Decimal((i * n + B) / f_3).to_integral_value(rounding = ROUND_FLOOR)
        if Decimal(m_max - m_min) < 1:
            return m_min

def attack():
    n, e, l, c = get_attack_params()

    n_int = int(n, 16)
    e_int = int(e, 16)
    k, c_int = [int(i, 16) for i in c.split(":")]
    B = 2 ** (8 * (k - 1))

    f_1 = step_1(e_int, n_int, c_int, k, l)

    print("f_1 previous", f_1 / 2)
    print("f_1", f_1)

    f_2 = step_2(f_1, n_int, B, e_int, c_int, k, l)

    print("f_2 previous", f_2 - int(f_1 / 2))
    print("f_2", f_2)

    m_min = step_3(f_2, n_int, B, e_int, c_int, k, l)
    
    print(m_min)
    print("")
    print(hex(int(m_min)))

if __name__ == "__main__":
    attack()