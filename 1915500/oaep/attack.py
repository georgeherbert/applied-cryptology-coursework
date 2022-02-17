import sys
import subprocess

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

    print(int_to_pretty_hex(1)) # 1:01
    print(int_to_pretty_hex(17)) # 1:11
    print(int_to_pretty_hex(255)) # 1:FF
    print(int_to_pretty_hex(256)) # 2:0100

    # response = interact(label, guess)
    # print(response)

if __name__ == "__main__":
    attack()