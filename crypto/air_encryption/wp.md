### 题目

连上之后给了6次交互机会, 但其中最少有一次需要用来`set key`

有三个选项:
+ set key : 初始化`aes-ctr`的counter
+ guess num: 每猜中一次随机数, 分数+1
+ get flag : 当分数不为4的时候, 发送的为有填充的加密的flag, 分数为4的时候发送明文flag

### 思路
由于题目`set key`没有校验次数, 可以多次重置密钥, 且密钥为每一次连接生成的随机值, 加上`aes-ctr`的特性, 只需要获取到足够长的明文即可

在`guess key`中, 猜对随机数服务端会发送填充加密后的`right`, 猜错随机数会发送填充加密后`wrong`, 实际上, 这里的明文都不够长, 

于是这样会出现只能获取到一半flag的情况。

正确是思路的是故意输入不符合要求的命令,  由于`self.send(b'something wrong, check your input')`, 填充和加密操作被内置到了`send`方法里面, 所以这里会发送很长的密文, 重复三次, 去除重合的部分即可得到足够长的密钥流

于是6次机会 = 1次`set key`初始化 + 3次报错`guess num`获取密钥流 + 1次`set key`重置密钥流 + 1次`get flag`获取加密后的flag

本地解密即可


### exp
```python
#!/usr/bin/python
from pwn import *
from pwnlib.util.iters import mbruteforce
from hashlib import sha256
import string
import time
import binascii
context.log_level = 'debug'
r = remote('happi0.club', 10086)

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

#b'\x8a\xa8\x83\xed\xe9\xe0\xe5\x11\xf4\x9c\xcc\xb6K\x91\xbb\xa9\xf0\xd4\t\x15\x19r\xf5Z\x9d.\x9368\x90\xe8\xd5flag{c836b2abae33d2e5b9a0e50b28ba5e95}\n\n\n\n\n\n\n\n\n\n'
```
