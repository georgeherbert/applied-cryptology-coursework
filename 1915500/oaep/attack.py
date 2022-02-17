import sys
import subprocess

TARGET = subprocess.Popen(
    args = sys.argv[1],
    stdin = subprocess.PIPE,
    stdout = subprocess.PIPE
)
TARGET_IN = TARGET.stdin
TARGET_OUT = TARGET.stdout

def interact():
    TARGET_IN.write("10:0A774558EC7D0C748FCC53DBAEF82D85\n".encode())
    TARGET_IN.write("80:2C1E28DDDBF06CD7F8EE16DA9D19079A92193A2EB54DBA01278CDEB17EB1A5D3DA2ECA6F6F217C48A17AFEC598B89AB655F3A4373609C6C6F0E1711DC7F0F23D5480F3B54C7EA6E69EB78ADEA6C74F93ED8BD40A7498D205258BD5FA71331ABCFA278CF4E3542183DEB27401FE93BDA75498C31587BA207595CFBE551ECC450B\n".encode())
    TARGET_IN.flush()
    return int(TARGET_OUT.readline().strip())

def attack():
    response = interact()
    print(response)

if __name__ == "__main__":
    attack()