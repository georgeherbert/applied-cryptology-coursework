import sys
import subprocess
import random
from Crypto.Cipher import AES

TARGET = subprocess.Popen(
    args = f"./{sys.argv[1]}",
    stdin = subprocess.PIPE,
    stdout = subprocess.PIPE
)
TARGET_IN = TARGET.stdin
TARGET_OUT = TARGET.stdout

TRACES = 20

HAMMING_WEIGHT_S_BOX = [
    4, 5, 6, 6, 5, 5, 6, 4, 2, 1, 5, 4, 7, 6, 5, 5,
    4, 2, 4, 6, 6, 4, 4, 4, 5, 4, 3, 6, 4, 3, 4, 2,
    6, 7, 4, 3, 4, 6, 7, 4, 3, 4, 5, 5, 4, 4, 3, 3,
    1, 5, 3, 4, 2, 4, 2, 4, 3, 2, 1, 4, 6, 4, 4, 5,
    2, 3, 3, 3, 4, 5, 4, 2, 3, 5, 5, 5, 3, 5, 5, 2,
    4, 4, 0, 6, 1, 6, 4, 5, 4, 5, 6, 4, 3, 3, 3, 6,
    3, 7, 4, 7, 3, 4, 4, 3, 3, 6, 1, 7, 2, 4, 6, 3,
    3, 4, 1, 5, 3, 5, 3, 6, 5, 5, 5, 2, 1, 8, 6, 4,
    5, 2, 3, 5, 6, 5, 2, 4, 3, 5, 6, 5, 3, 5, 3, 5,
    2, 2, 5, 5, 2, 3, 2, 2, 3, 6, 4, 2, 6, 5, 3, 6,
    3, 3, 4, 2, 3, 2, 2, 4, 3, 5, 4, 3, 3, 4, 4, 5,
    6, 3, 5, 5, 4, 5, 4, 4, 4, 4, 5, 5, 4, 5, 5, 1,
    5, 4, 3, 4, 3, 4, 4, 4, 4, 6, 4, 5, 4, 6, 4, 3,
    3, 5, 5, 4, 2, 2, 6, 3, 3, 4, 5, 5, 3, 3, 4, 5,
    4, 5, 3, 2, 4, 5, 4, 3, 5, 4, 4, 5, 5, 4, 2, 7,
    3, 3, 3, 3, 7, 5, 2, 3, 2, 4, 4, 4, 3, 3, 6, 3
]

def interact(block, tweak):
    TARGET_IN.write(f"{block}\n".encode())
    TARGET_IN.write(f"10:{tweak:0{16 * 2}x}\n".encode())
    TARGET_IN.flush()
    trace = [int(i) for i in TARGET_OUT.readline().strip().split(b",")[1:]]
    trace_start = trace[:3000]
    trace_end = trace[-5000:]
    plaintext = int(TARGET_OUT.readline().strip().split(b":")[1], 16)
    return trace_start, trace_end, plaintext

def get_traces():
    tweaks = []
    traces_start = []
    traces_end = []
    plaintexts = []
    for _ in range(TRACES):
        tweak = random.randrange(0, 2 ** 128)
        trace_start, trace_end, plaintext = interact(0, tweak)
        tweaks.append(tweak)
        traces_start.append(trace_start)
        traces_end.append(trace_end)
        plaintexts.append(plaintext)
    return tweaks, traces_start, traces_end, plaintexts

def extract_byte(num, byte):
    value = (num >> (8 * byte) & 0xFF)
    return value

def pearsons(x, y):
    x_mean = sum(x) / len(x)
    y_mean = sum(y) / len(y)
    numerator = sum([(x_i - x_mean) * (y_i - y_mean) for x_i, y_i in zip(x, y)])
    denominator = (sum([(x_i - x_mean) ** 2 for x_i in x]) * sum([(y_i - y_mean) ** 2 for y_i in y])) ** (1 / 2)
    return numerator / denominator

# TODO: Remove 3000
def calc_byte(byte, tweaks, traces):
    key_guess = 0
    max_correlation = 0
    for key_byte in range(256):
        hamming_matrix_column = [HAMMING_WEIGHT_S_BOX[extract_byte(tweak, byte) ^ key_byte] for tweak in tweaks]
        for i in range(len(traces[0])):
            correlation = pearsons([trace[i] for trace in traces], hamming_matrix_column)
            if correlation > max_correlation:
                max_correlation = correlation
                key_guess = key_byte
        # print(key_byte, max_correlation)

    print(key_guess, max_correlation)
    return key_guess

def calc_key_2(tweaks, traces):
    key_2 = 0
    # For each byte of the key
    for i in range(16):
        next_byte = calc_byte(i, tweaks, traces)
        key_2 += next_byte * (256 ** i)
    return key_2

def calc_ts(key_2, tweaks):
    ts = []
    enc = AES.new(key_2.to_bytes(16, byteorder = "big"))
    for tweak in tweaks:
        tweak_encrypted = enc.encrypt(tweak.to_bytes(16, byteorder = "big"))
        ts.append(int.from_bytes(tweak_encrypted, "big"))
    return ts

def calc_pps(plaintexts, ts):
    return [p ^ t for p, t in zip(plaintexts, ts)]

# TODO: Remove -5000
def calc_byte_2(byte, pps, traces):
    key_guess = 0
    max_correlation = 0
    for key_byte in range(256):
        hamming_matrix_column = [HAMMING_WEIGHT_S_BOX[extract_byte(pp, byte) ^ key_byte] for pp in pps]
        for i in range(len(traces[0])):
            correlation = pearsons([trace[i] for trace in traces], hamming_matrix_column)
            if correlation > max_correlation:
                max_correlation = correlation
                key_guess = key_byte
        print(key_byte, max_correlation)

    print(key_guess, max_correlation)
    return key_guess

def calc_key_1(pps, traces):
    key_1 = 0
    for i in range(16):
        next_byte = calc_byte_2(i, pps, traces)
        key_1 += next_byte * (256 ** i)
    print(key_1)
    return key_1

def attack():
    tweaks, traces_start, traces_end, plaintexts = get_traces()
    
    # key_2 = calc_key_2(tweaks, traces_start)
    key_2 = 320877140613514890691378064330247603255
    print(key_2)
    
    ts = calc_ts(key_2, tweaks)
    pps = calc_pps(plaintexts, ts)

    key_1 = calc_key_1(pps, traces_end)

if  __name__ == "__main__":
    attack()

# TODO: Variable trace lengths - maybe padding
# TODO: Remove the manual using of first N samples
# TODO: Parallelise