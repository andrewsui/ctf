# Write-Ups of CTF Style Challenges

Below is a selection of write-ups for some of the more interesting challenges:
- [pwn.college - rev_level14](./pwn.college/2020/04-Rev/14_testing1/index.html) (binary reverse engineering)
- [ROP Emporium - pivot](./rop_emporium/solutions/x86_64/07-pivot/index.html) (return oriented programming)
- [ROP Emporium - ret2csu](./rop_emporium/solutions/x86_64/08-ret2csu/index.html) (return oriented programming)

[pwn.college](https://pwn.college/) has many amazing challenges, including one level that requires reverse engineering a [JIT compiler](https://github.com/pwncollege/challenges/raw/master/toddler1/level8_testing1). Due to their [write-up policy](https://pwn.college/#collaboration-livestream-and-writeup-policy), I am unable to share a write-up for this particular level. It is however a lot of fun and teaches some valuable concepts regarding JIT compilers, JIT spraying and how vulnerabilities can still be present despite having all standard security mitigations (e.g. DEP, stack canary, etc) enabled.
