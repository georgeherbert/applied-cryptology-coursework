import sys
import subprocess
import math

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

def int_to_pretty_hex(value_int):
    value_hex = f"{value_int:x}"
    value_hex_length = len(value_hex)
    odd_length = value_hex_length % 2 == 1
    if odd_length:
        value_hex = "0" + value_hex
    num_octets = value_hex_length // 2 + odd_length
    return f"{num_octets:x}:{value_hex}"

def interact(label, ciphertext):
    TARGET_IN.write(f"{label}\n".encode())
    TARGET_IN.write(f"{ciphertext}\n".encode())
    TARGET_IN.flush()
    return int(TARGET_OUT.readline().strip())

def attack():
    modulus, public_exponent, label, ciphertext = get_attack_params()

    modulus_int = int(modulus, 16)
    exponent_int = int(public_exponent, 16)
    ciphertext_int = int(ciphertext.split(":")[1], 16)

    k = math.log(modulus_int, 256)
    B = 2 ** (8 * (k - 1))

    f_1 = 1
    response = 0
    
    while response != 2:
        f_1 *= 2
        guess = (pow(f_1, exponent_int, modulus_int) * ciphertext_int) % modulus_int
        guess_hex = int_to_pretty_hex(guess)
        response = interact(label, guess_hex)
        print(response)

    f_2 = math.floor((modulus_int + B) / B) * f_1 // 2
    print(f_2)

    guess = (pow(f_2, exponent_int, modulus_int) * ciphertext_int) % modulus_int
    guess_hex = int_to_pretty_hex(guess)
    response = interact(label, guess_hex)
    print(response)

    m_min = math.ceil(modulus_int / f_2)
    m_max = math.floor((modulus_int + B) / f_2)
    
    f_tmp = math.floor((2 * B) / (m_max - m_min))
    i = math.floor((f_tmp * m_min) / modulus_int)

    f_3 = math.ceil((i * modulus_int) / m_min)

    guess = (pow(f_3, exponent_int, modulus_int) * ciphertext_int) % modulus_int
    guess_hex = int_to_pretty_hex(guess)
    response = interact(label, guess_hex)
    print(response)
    
    # response = interact(label, ciphertext)
    # print(response)

if __name__ == "__main__":
    attack()