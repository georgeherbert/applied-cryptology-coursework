import sys
import subprocess
import math
from decimal import Decimal, getcontext, ROUND_CEILING, ROUND_FLOOR
from hashlib import sha1
import time

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

def calc_attack_params_int(n, e, l, c):
    n_int = int(n, 16)
    e_int = int(e, 16)
    lLength, l_int = [int(i, 16) for i in l.split(":")]
    k, c_int = [int(i, 16) for i in c.split(":")]
    b = 2 ** (8 * (k - 1))
    return n_int, e_int, lLength, l_int, k, c_int, b 

def int_to_pretty_hex(value_int, k):
    return f"{k:x}:{value_int:0{k * 2}x}"

def interact(l, c):
    TARGET_IN.write(f"{l}\n".encode())
    TARGET_IN.write(f"{c}\n".encode())
    TARGET_IN.flush()
    return int(TARGET_OUT.readline().strip())

def send_to_oracle(f, e, n, c, k, l):
    value = (pow(f, e, n) * c) % n
    value_pretty = int_to_pretty_hex(value, k)
    return interact(l, value_pretty)

def step_1(e, n, c, k, l):
    f_1 = 2
    interactions = 1
    while send_to_oracle(f_1, e, n, c, k, l) != 1:
        f_1 *= 2
        interactions += 1
    return f_1, interactions

def step_2(f_1, interactions, n, b, e, c, k, l):
    f_2 = int(math.floor((n + b) / b) * (f_1 / 2))
    interactions += 1
    while send_to_oracle(f_2, e, n, c, k, l) != 2:
        f_2 += int(f_1 / 2)
        interactions += 1
    return f_2, interactions

def step_3(f_2, n, b, interactions, e, c, k, l):
    getcontext().prec = 500

    m_min = Decimal(n / f_2).to_integral_value(rounding = ROUND_CEILING)
    m_max = Decimal((n + b) / f_2).to_integral_value(rounding = ROUND_FLOOR)
    
    while m_min != m_max:
        f_tmp = Decimal((2 * b) / (m_max - m_min)).to_integral_value(rounding = ROUND_FLOOR)
        i = Decimal((f_tmp * m_min) / n).to_integral_value(rounding = ROUND_FLOOR)
        f_3 = Decimal((i * n) / m_min).to_integral_value(rounding = ROUND_CEILING)
        response = send_to_oracle(int(f_3), e, n, c, k, l)
        interactions += 1
        if response == 1:
            m_min = Decimal((i * n + b) / f_3).to_integral_value(rounding = ROUND_CEILING)
        elif response == 2:
            m_max = Decimal((i * n + b) / f_3).to_integral_value(rounding = ROUND_FLOOR)
    return int(m_min), interactions

# https://en.wikipedia.org/wiki/Mask_generation_function#Example_code
def i2osp(integer):
    return b"".join([chr((integer >> (8 * i)) & 0xFF).encode() for i in reversed(range(4))])

def mgf1(input_str, length):
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter)
        output += sha1(input_str + C).digest()
        print("\n", (input_str + C).hex(), "\n")
        counter += 1
    return output[:length]

def xor(x, y):
    return bytes([x_i ^ y_i for x_i, y_i in zip(x, y)])

def calc_m_from_em(em_int, k, l_int, lLength):
    em = int(em_int).to_bytes(k, byteorder = "big")
    # print(em.hex())
    assert em[0] == 0x00, "Y must equal 0x00"

    masked_seed = em[1:21]
    masked_db = em[21:]
    seed_mask = mgf1(masked_db, 20)
    seed = xor(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - 21)
    db = xor(masked_db, db_mask)

    lhash = sha1(l_int.to_bytes(lLength, byteorder = "big")).digest()
    lhash_ = db[:20]
    assert lhash_ == lhash, "lHash' must equal lHash"

    # print("encoded_message:", em.hex())
    # print("masked_seed:", masked_seed.hex())
    # print("masked_db:", masked_db.hex())
    # print("seed_mask:", seed_mask.hex())
    # print("db_mask:", db_mask.hex())
    # print("seed:", seed.hex())
    # print("db:", db.hex())
    # print("lhash:", lhash.hex())

    m = db[db.index(0x01) + 1:]

    print("message:", m.hex())

    return m

def attack():
    print("Starting attack...")
    start = time.time()
    n, e, l, c = get_attack_params()
    n_int, e_int, lLength, l_int, k, c_int, b = calc_attack_params_int(n, e, l, c)

    f_1, interactions = step_1(e_int, n_int, c_int, k, l)
    print("f_1:", f_1)
    f_2, interactions = step_2(f_1, interactions, n_int, b, e_int, c_int, k, l)
    print("f_2:", f_2)
    em_int, interactions = step_3(f_2, n_int, b, interactions, e_int, c_int, k, l)

    m = calc_m_from_em(em_int, k, l_int, lLength)
    # m = 0x10219ac029e1c1c22028f7ecf1b3de757830df8e68b0b78488ea8c9efdeb38
    stop = time.time()
    print("Attack complete")
    print("Attack time:", stop - start, "seconds")
    print("Target material (base 16):", m.hex())
    print("Interactions with device (base 10):", interactions)

if __name__ == "__main__":
    attack()