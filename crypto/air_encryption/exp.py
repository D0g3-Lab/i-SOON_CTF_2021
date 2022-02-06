#!/usr/bin/python
from pwn import *
from pwnlib.util.iters import mbruteforce
from hashlib import sha256
import string
import time
import binascii
context.log_level = 'debug'
r = remote('127.0.0.1', 10086)

def padding( msg):
    return  msg + chr((16 - len(msg)%16)).encode() * (16 - len(msg)%16)

def xor_bytes(var, key):
    return bytes(a ^ b for a, b in zip(var, key))

def decrypt(ct):
    msg = padding(b'something wrong, check your input')
    pt = xor_bytes(msg, ct)
    return pt

# pow
data = r.recvline()
print(data[12:28], data[33:97])
found = mbruteforce(lambda x:sha256(x.encode() + data[12:28]).hexdigest().encode() == data[33:97], string.ascii_letters+string.digits, 4)
r.sendline(found)
r.recvline()

# set key
n = int(binascii.unhexlify(r.recvline()[:-1]))
d = int(binascii.unhexlify(r.recvline()[:-1])) // 2
c = int(binascii.unhexlify(r.recvline()[:-1]))
m = pow(c,d,n)
r.sendline(b'set key:' + str(m).encode())
time.sleep(0.5)

# guess num
key_stream = b''
for i in range(3):
    r.sendline(b'happi0')
    time.sleep(0.5)
    ct = binascii.unhexlify(r.recvline()[:-1])
    pt = decrypt(ct)
    if i != 2:
        key_stream += pt[:16]
    else:
        key_stream += pt
    print('pt:' + str(pt) + '\n' + 'length: ' + str(len(pt)))
    print('key_stream:' + str(key_stream) + '\n' + 'length: ' + str(len(key_stream)) + '\n')

# reset key
r.sendline(b'set key:' + str(m).encode())
time.sleep(0.5)
r.sendline(b'get flag')
time.sleep(0.5)

# decrypt flag
flag = binascii.unhexlify(r.recvline()[:-1])
print(flag, type(flag), key_stream)
flag = xor_bytes(flag, key_stream)
print(flag)
