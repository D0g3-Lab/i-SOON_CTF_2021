#!/usr/bin/python
import socketserver
import random
import os
import string
import binascii
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter 
from Crypto.Util.number import getPrime
from hashlib import sha256
import gmpy2
flag = b'flag{c836b2abae33d2e5b9a0e50b28ba5e95}'

def init():
    q = getPrime(512)
    p = getPrime(512)
    e = getPrime(64)
    n = q*p
    phi = (q-1) * (p-1)
    d = gmpy2.invert(e, phi)
    hint = 2 * d + random.randint(0, 2**16) * e * phi
    mac = random.randint(0, 2**64)
    c = pow(mac, e, n)
    counter = random.randint(0, 2**128)
    key = os.urandom(16)
    score = 0
    return n, hint, c, counter, key, mac, score

class task(socketserver.BaseRequestHandler):

    def POW(self):
        random.seed(os.urandom(8))
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
        result = hashlib.sha256(proof.encode('utf-8')).hexdigest()
        self.request.sendall(("sha256(XXXX+%s) == %s\n" % (proof[4:],result)).encode())
        self.request.sendall(b'Give me XXXX:\n')
        x = self.recv()
        
        if len(x) != 4 or hashlib.sha256((x+proof[4:].encode())).hexdigest() != result: 
            return False
        return True

    def recv(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def padding(self, msg):
        return  msg + chr((16 - len(msg)%16)).encode() * (16 - len(msg)%16)

    def encrypt(self, msg):
        msg = self.padding(msg)
        if self.r != -1:
            self.r += 1
            aes = AES.new(self.key, AES.MODE_CTR, counter = Counter.new(128, initial_value=self.r))
            return aes.encrypt(msg)
        else:
            return msg

    def send(self, msg, enc=True):
        print(msg, end= '   ')
        if enc:
            msg = self.encrypt(msg)
        print(msg, self.r)
        self.request.sendall(binascii.hexlify(msg) + b'\n')

    def set_key(self, rec):
        if self.mac == int(rec[8:]):
            self.r = self.counter

    def guess_num(self, rec):
        num = random.randint(0, 2**128)
        if num == int(rec[10:]):
            self.send(b'right')
            self.score += 1
        else:
            self.send(b'wrong')

    def get_flag(self, rec):
        assert self.r != -1
        if self.score ==  5:
            self.send(flag, enc=False)
        else:
            self.send(os.urandom(32) +  flag)

    def handle(self):
        self.r = -1

        if not self.POW():
            self.send(b'Error Hash!', enc= False)
            return

        self.n, self.hint, self.c ,self.counter, self.key, self.mac, self.score = init()

        self.send(str(self.n).encode(), enc = False)
        self.send(str(self.hint).encode(), enc = False)
        self.send(str(self.c).encode(), enc = False)

        for _ in range(6):
            rec = self.recv()
            if rec[:8] == b'set key:':
                self.set_key(rec)
            elif rec[:10] == b'guess num:':
                self.guess_num(rec)
            elif rec[:8] == b'get flag':
                self.get_flag(rec)
            else:
                self.send(b'something wrong, check your input')

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

def main():
    HOST, PORT = '127.0.0.1', 10086
    server = ForkedServer((HOST, PORT), task)
    server.allow_reuse_address = True
    server.serve_forever()

if __name__ == '__main__':
    main()
