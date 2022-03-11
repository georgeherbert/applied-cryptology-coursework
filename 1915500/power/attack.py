import sys
import subprocess
import random

TARGET = subprocess.Popen(
    args = f"./{sys.argv[1]}",
    stdin = subprocess.PIPE,
    stdout = subprocess.PIPE
)
TARGET_IN = TARGET.stdin
TARGET_OUT = TARGET.stdout

TRACES = 100

def interact(j, i):
    TARGET_IN.write(f"{j}\n".encode())
    TARGET_IN.write(f"10:{i:0{16 * 2}x}\n".encode())
    TARGET_IN.flush()
    trace = TARGET_OUT.readline().strip()
    message = TARGET_OUT.readline().strip()
    return trace, int(message.split(b":")[1], 16)

def get_traces_messages():
    traces = []
    messages = []
    for _ in range(TRACES):
        power_consumption, message = interact(0, random.randrange(0, 16777216))
        traces.append(power_consumption)
        messages.append(message)
    return traces, messages

def attack():
    traces, messages = get_traces_messages()
    print(traces)
    print(messages)

if  __name__ == "__main__":
    attack()