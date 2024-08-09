import os
import time
import signal
import pickle
import socket
import subprocess

VERIFICATION_LOG = 'verification_failures.log'
CHECKSUM_LOG = 'checksum_failures.log'

with open('payload_dump.bin', 'rb') as f:
    payloads = pickle.load(f, encoding="bytes")[:250]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
cmd = "python server.py --keys '{\"0x42\": \"key.bin\"}' --binaries '{\"0x42\": \"cat.jpg\"}' -d '0' -p '1337'"
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

time.sleep(1)

for payload in payloads:
    sock.sendto(payload, ('127.0.0.1', 1337))
    time.sleep(0.001)

time.sleep(1)

with open(VERIFICATION_LOG, 'r') as v, open(CHECKSUM_LOG, 'r') as c:
    verification_failures = v.read()
    checksum_failures = c.read()

expected_verification = "0x42\n3703\nfd2bc562a95c4924d27f9f81de052fbab650f0c2989ee9f4e826244e7c1f0e66\n26a4fcaa2167342136272e1d2814b7c73ac995e1229fea8bffa536600cc57921\n\n"
expected_checksum = "0x42\n1109\n1119\n2165e3dd\n2165e24d\n\n"

if verification_failures == expected_verification and checksum_failures == expected_checksum:
    print("Log format is correct!")
else:
    print("Something isn't right...")

# Clean up
if os.path.exists(VERIFICATION_LOG):
    os.remove(VERIFICATION_LOG)
if os.path.exists(CHECKSUM_LOG):
    os.remove(CHECKSUM_LOG)
os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
sock.close()
