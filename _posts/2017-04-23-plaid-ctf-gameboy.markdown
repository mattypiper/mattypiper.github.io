---
layout: post
title:  "Plaid CTF 2017 - gameboy"
date:   2017-04-23 23:43:49 -0400
categories: ctf gameboy
comments: true
---

<img src="/assets/1024px-Game-Boy-FL.jpg" width="204" heigth="248" >

Author: mattypiper

Contributors: mattypiper, nopple, fringe, other team members

## Background

The [challenge tar.gz] contains a Gameboy (LR35902) emulator, a sample ROM, and output from dpkg -l. The emulator is a
64-bit position independent ELF executable. ROMs are read from stdin. The LCD screen is implemented by way of an ASCII
art style output, and buttons are read from stdin after the ROM is loaded - WASD for the D-Pad and UJIK for Start,
Select, A, and B.
The ROM included in the tar.gz is Apocalypse Now, which is available on the Internet with a 
matching MD5, so not of interest. The dpkg listing will eventually help with identifying the
libc version on the server.

## Bugs

1. Providing a 16-character ROM name will leak the address of the PIE's code section to stdout.

2. A custom opcode 0xED was added to the emulator's instruction set which performs an `XOR ($FF00 + C), A`. `$FF00` is
the IO port region, so this instruction provides a way to write to the IO ports with an 8-bit operand, similar to other
standard instructions like `LD ($FF00+C), A`. However, the C operand is interpreted as a signed quantity, allowing
effectively: `XOR (C), A` where C is in the range [-128, 127]. This allows addressing "negative" memory.

## Exploit

The emulator implements a state structure, containing pointers to various things and the LR35902 registers, and a 64KB
ROM space. The state structure and ROM space are allocated together in the heap:

```
+---------------+
|     ...       |   <-- heap base
+---------------+  
|  ptr_emu_mem  |   <-- base + 0x10, points to base + 0x80 (ROM space)
+---------------+
|  ptr_oam_mem  |
+---------------+
|     ...       |
| other stuff   |
|     ...       | 
+---------------+
|               |
| emu registers |
|               |
+---------------+
|               |
|               |
+---------------+
|   ROM space   |   <-- base + 0x80
|     ...       |
|     ...       |
+---------------+
```

If we start with an end goal of overwriting a Global Offset Table (GOT) pointer as a means of getting a shell, we need
to create a GameBoy ROM that writes to the GOT. From bug #1, we have a pointer to the PIE base, so we can calculate
where the GOT is based on that. But there's one problem. The pointer is written to stdout _after_ the ROM is sent to
emulator. So there's no way for the ROM to know the PIE base address without somehow writing it back to stdin. The only
IO available is the ASCII art LCD screen and the joypad input. So, the first thing the ROM needs to do is read the
pointer from its "standard input", aka the joypad. With some clever Python and LR35902 ROM code, we can encode 2-bits at
a time onto the WASD joypad, and write that information into the emulator's stdin using the WASD controls.
The [joypad input](http://bgb.bircd.org/pandocs.htm#joypadinput) can be read at register `$FF00` by
first selecting the directional pad, and then reading the value. We store the leaked pointer off into Game Boy
RAM for later usage.

{% highlight nasm %}
    ; select directional pad
    LD A, $20
    LD [$FF00], A

    ; read value
    LD A, [$FF00]
{% endhighlight %}

Now that the GameBoy code knows where the GOT is, we need a way to write there. If we use bug #2, we can write
backwards from the start of ROM and corrupt the emulator state. At this point, there is a choice to make
about which byte of the emulator state to corrupt first. We opted to change _ptr_emu_mem_ to rebase the emulator ROM
down by 0x80. This way the GB code can read/write the emulator state directly with simple LD instructions targeting
addresses around 0. A single `XOR ($FF00 + $90), $80` instruction changes the low byte of _ptr_emu_mem_ for 0x80 to
0x00, and the ROM is rebased.

There are a few side effects of rebasing the GameBoy ROM that we had to consider.

1. On the next cycle of the emulator, the next instruction will be fetched 0x80 bytes lower than the
previous PC. Prepare for this by placing a landing pad there.
2. All of GameBoy memory is remapped down by 0x80. This includes the IO ports at 0xFF00.
The emulator checks the value of certain IO registers every iteration. Due to the rebase, the values of all the IO
registers have probably changed from their initial value to zero. This causes a few things to go awry, but nothing that
crashes the emulator, and our GB code continues on.

So now we've rebased and we can change any of the pointers in the emulator state block. Back to our goal of
overwriting the GOT. From earlier RE of the emulator, we knew there was a DMA transfer operation that would
copy 160 bytes from any GB ROM page to the "Object Attribute Memory" or OAM. The OAM is
mapped at 0xFE00 in the device, so it could simply be accessed with offset 0xFE00 from _ptr_emu_mem_. But instead, the
emulator implemented the DMA transfer using a separate pointer specifically for performing DMA transfers. Now that the
emulator state block is mapped into GB ROM, we can change the OAM pointer to anywhere in 64-bit process memory, including
outside of the GameBoy's usual 16-bit boundary. After changing the pointer with a few LD instructions, we simply
initiate a DMA transfer, using `LDH [$FF46], A`, and we get a 160 byte copy from the GB ROM space to anywhere. Now we
have a good write primitive.

The next problem is reading the GOT. In order to update the GOT with some other libc address, we need to know
where libc is loaded in memory. But all we have so far is a write primitive, not a read primitive.

We thought for a few minutes and could not come up with an easy way to read outside of emulator ROM space. There was
much deliberation (and groaning) about the potential of using the LCD screen to leak the GOT back to stdout, and then
push the leaked GOT pointer back to the GB ROM code using the WASD D-Pad again. This is possible because we could
also change the video memory and display buffer pointers in the emulator state. So I'm sure that would work, and I really
hope other teams attempted this, but after reading about tiles, palettes, and parsing the ASCII screen, I sought
other avenues.

Another option that was apparent was to rebase the ROM again. We'd already done it once. If we rebased the ROM
down to the read/write data section of the x64 PIE and restart the emulator, we would have read/write access
to the GOT by placing the GameBoy's 64KB "window" around the GOT. We were a bit adverse to this idea at first
because we might lose control of the emulator state block. But it turned out that isn't really true.
We could've saved off a heap pointer used a DMA transfer to maintain control of the emulator state.
But it turned out that this is the last rebase and we didn't need the emulator state anymore.

Rebasing again requires us to have code ready for the emulator when it starts up again in the new location.
So we first use another DMA transfer to copy code from GB ROM space to the x64 PIE data section,
then rebase the 64KB GB memory.

Rebasing was trivial the first time because it was a one byte adjustment to _ptr_emu_mem_, which can be accomplished using
a GameBoy 8-bit memory write. To rebase from the heap to the PIE requires a multibyte write; an "atomic" update, if you
will. If we were to change only one byte of _ptr_emu_mem_ in a GB instruction, essentially the emulator is rebased
immediately at the next cycle when it goes to fetch PC. The heap and the Position Independent Executable are too far
away for a one-byte write to be useful. So, back to our friend, DMA transfer. If we make a copy of the emulator state in
GB RAM, we can change _ptr_emu_mem_ without causing havoc, and then "atomically" write the state copy back to its
real location using the memcpy provided by the DMA transfer. While we're mucking around with the emulator state object,
we can also fix the emulator's PC register to point to where it needs to be after the rebase is complete.

We chose addresses such that our code would be copied right after the GOT table. We had to be careful to make
sure the IO ports at 0xFF00 were still mapped so as not to crash the process. With some careful selection of both the GB
ROM base and the emulator PC, we were able to get the emulator to continue execution inside of its ROM space, but
mapped into the data segment of the x64 PIE. Once this was accomplished, we could read and write to the GOT directly
using GameBoy LD instructions.

For the GOT overwrite, we chose usleep as our target, as it is executed periodically by the emulator. For the value to
overwrite, we used a pointer to a system("/bin/sh") gadget already inside of libc. This gadget is in the
`do_system` function of libc, and effectively allows for a single GOT pointer overwrite to give you a shell.
Note that we had to update the offset to this gadget based on whether we were testing on a local system or sending
to the Plaid CTF challenge server.

{% highlight bash %}
gdb-peda$ x/10i 0x00007ffff7a5847c
   0x7ffff7a5847c <do_system+956>:	mov    rax,QWORD PTR [rip+0x37aa25]        # 0x7ffff7dd2ea8
   0x7ffff7a58483 <do_system+963>:	lea    rdi,[rip+0x139c79]        # 0x7ffff7b92103
   0x7ffff7a5848a <do_system+970>:	lea    rsi,[rsp+0x30]
   0x7ffff7a5848f <do_system+975>:	mov    DWORD PTR [rip+0x37d227],0x0        # 0x7ffff7dd56c0 <lock>
   0x7ffff7a58499 <do_system+985>:	mov    DWORD PTR [rip+0x37d22d],0x0        # 0x7ffff7dd56d0 <sa_refcntr>
   0x7ffff7a584a3 <do_system+995>:	mov    rdx,QWORD PTR [rax]
   0x7ffff7a584a6 <do_system+998>:	call   0x7ffff7ad6d20 <__execve>
gdb-peda$ x/s 0x7ffff7b92103
0x7ffff7b92103:	"/bin/sh"
{% endhighlight %}

#### Other useful tidbits:

* To help debugging, it's useful to have ways to inspect the emulator state and operation. The state block is always fixed
at `heap_base + 0x10`, so no tricks required there. It was trivial to examine the emulator program counter and other
registers at any point in time. But it's also good to jot down the address (PIC offset) of certain key emulator
instructions. In our case, I often set GDB breakpoints on instruction handlers for the 0xED XOR opcode address (0x1A27),
the memcpy address of the DMA transfer (0xF32), as well as the overarching "next instruction fetch unit" of the emulator
(0x118D).  Especially when rebasing, breaking in GDB at the instruction fetcher (0x118D) gives us the PC in $RAX, and
`x/16bx $r8` gives us the next 16 op codes of the program. However, breaking at every emulated instruction is too slow,
so it's also good to be ready with breakpoints at other key points in the program like the XOR and the DMA.
Additionally, it helped to sprinkle the GameBoy code liberally with breakpoints, to inspect the program state
before and after things  like DMA transfers.
For a "GameBoy Breakpoint", choose an instruction with few side effects, such as the clear flags
register instruction `CCF` at 0x2A43. Then I just put the CCF instruction anywhere I needed to stop the emulator and
inspect things.

* Turn off ASLR for most of development.

* We used [rgbds] to assemble, link, and fix our ROMs.
The nonstandard XOR instruction can be assembled using `DB $EB`.

* The [LR35902 opcode table] and [BGB documentation] were invaluable while working on this challenge.

## Solution Files

* [Python script]
* [Gameboy assembly]
* [rgbds build script]

## Flag

`PCTF{gameboy?_thats_sexist_why_isnt_it_just_gamechild?}`

[challenge tar.gz]: /files/ctf/gameboy/gameboy_c7a4e5cde2194af9b66aa5fbc724c785.tar.gz
[LR35902 opcode table]: http://pastraiser.com/cpu/gameboy/gameboy_opcodes.html
[BGB documentation]: http://bgb.bircd.org/pandocs.htm
[rgbds]: https://github.com/rednex/rgbds
[python script]: /files/ctf/gameboy/gameboy.py
[gameboy assembly]: /files/ctf/gameboy/gameboy.asm
[rgbds build script]: /files/ctf/gameboy/build.sh

