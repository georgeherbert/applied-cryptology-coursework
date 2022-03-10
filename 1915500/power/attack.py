import sys
import subprocess

TARGET = subprocess.Popen(
    args = f"./{sys.argv[1]}",
    stdin = subprocess.PIPE,
    stdout = subprocess.PIPE
)
TARGET_IN = TARGET.stdin
TARGET_OUT = TARGET.stdout

def attack():
    pass

if  __name__ == "__main__":
    attack()