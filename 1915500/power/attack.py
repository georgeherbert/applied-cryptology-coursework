import sys
import subprocess

TARGET = subprocess.Popen(
    args = f"./{sys.argv[1]}",
    stdin = subprocess.PIPE,
    stdout = subprocess.PIPE
)
TARGET_IN = TARGET.stdin
TARGET_OUT = TARGET.stdout

def interact(j, i):
    TARGET_IN.write(f"{j}\n".encode())
    TARGET_IN.write(f"10:{i:0{16 * 2}x}\n".encode())
    TARGET_IN.flush()
    power_consumption = TARGET_OUT.readline().strip()
    m = TARGET_OUT.readline().strip()
    return power_consumption, m

def attack():
    power_consumption, m = interact(10, 100)
    print(power_consumption)
    print(m)

if  __name__ == "__main__":
    attack()