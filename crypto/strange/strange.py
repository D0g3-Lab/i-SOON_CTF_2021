from Crypto.Util.number import *
import os

flag = b'D0g3{}'
m = bytes_to_long(flag)

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 3

hint = bytes_to_long(os.urandom(256))

m1 = m | hint
m2 = m & hint

c = pow(m1, e, n)

with open('output.txt','a') as f:
    f.write(str([n,c,m2,hint]))
    f.close()
