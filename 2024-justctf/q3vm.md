# justCTF 2024 teaser - q3vm

> ## [q3vm](https://2024.justctf.team/challenges/8)
>
> You want to play Quake 3 with friends. Prepare a nice game plugin!
> 
> Author: Rivit
>
> ```sh
> nc q3vm.nc.jctf.pro 1337
> ```

**Category:** pwn

**Provided files:**
 - [q3vm.tar.gz](https://s3.cdn.justctf.team/1c4b1843-9931-485a-b07c-12a305e70108/q3vm.tar.gz): contains the Docker setup of the challenge + q3vm binary

**Solved by**: Popax21 (writeup author), 0x6fe1be2

## Solution

The docker setup is a bare-bones wrapper around [q3vm](https://github.com/jnz/q3vm), an implementation of the Quake III Virtual Machine used (as far as I know) to host mods / plugins / etc. The repository also contains an assembler as well as a primitive C compiler. Looking through the Dockerfile reveals that no custom patches are applied / specific commits are checked out, indicating that we must find a """zero day""" to break out of the VM and read the `flag.txt` file located in the file system root.

By reading the VM source code, we can observe that the virtual machine is based on a 32 bit stack-based architecture, containing two separate stacks:
 - the **`opstack`**, which is used for regular VM operations. It has a fixed size of 256 32 bit machine words, wrapping around when under/overflown due to its stack pointer / index being stored in a single byte. In the `q3vm` source, it is stored as a local array inside of `VM_CallInterpreted`.
 - the **`progstack`**, which is used for calling functions and storing their stack frames. It consists of a simple pointer into the VM's usual data segment. The executed bytecode can interact with this stack in one of four ways:
   - the `LOCAL` opcode: pushes the progstack pointer + an provided offset onto the opstack. This is used to obtain a pointer to a local variable / argument in the function's stack frame to dereference later.
   - the `ARG` opcode: this performs what is called "argument marshalling", where a value is popped from the opstack and stored at a certain offset in the progstack. This opcode is used to set up the arguments before calling another function using a `CALL` opcode. 
   - the `CALL` opcode: pushes the return address onto the progstack before jumping to the new function to execute, to be popped by `RET`. Notably, when the called function is a syscall (address < 0), it also pushes the syscall number (`-1 - <called addr>`) onto the progstack.
   - the `ENTER` / `LEAVE` opcodes: offset the progstack pointer by an arbitrary amount. Note that no constrains are placed onto the value of the progstack pointer - we can fully control it!

When scanning the code for vulnerabilities, three vulnerabilities can be found:
 - `VM_Call` (which is used to call the bytecode's main function) supports passing up to 12 arguments to the VM using varargs. However, it always marshals all 12 arguments to the progstack, even if no varargs are passed to the function! This results in a limited register / stack leak, which in practice turns out to not really be exploitable, since we only leak the bottom 32 bits of each register (not all 64 bits of a pointer required to bypass ASLR).

 - `VM_CallInterpreted` does not zero out the opstack, leaving it initially uninitialized. This, in combination with opcodes allowing access to uninitialized opstack slots (e.g. `PUSH`, which increments the stack pointer without actually storing anything in the corresponding slot), **allows for a stack leak, which can be used to determine the base address of libc / etc.**

 - While `ARG` bounds-checks the progstack pointer when writing to the progstack, `CALL` does not do so when pushing the return address / syscall number. Since the progstack pointer can be fully controlled by the user through the `ENTER` / `LEAVE` instructions, **this allows for an arbitrary OOB write outside of the VM's data segment!**
 
Since progstack is defined to be a 32 bit signed integer, we don't have an arbitrary-write primitive - the target address is required to be near the VM's data buffer in memory. Because the data buffer / segment is allocated on the heap, this means that in practice we have an arbitrary heap write primitive. However, since no relevant data structures (including the VM's main struct) live on the heap, in addition to our bytecode not being able to trigger arbitrary `malloc`s / `free`s which would be required for an heap exploit, it appears that this is probably isn't the correct path forward from here :/.

However, we can (ab)use the fact that large enough heap allocations trigger glibc to give us our own private `mmap`ed pages to fulfill the `malloc` request. In this case, the way virtual memory is allocated by the Linux kernel means that our VM data segment will end up right in front of libc :) - all we have to do is to ensure that our data segment is sufficiently big.

> [!NOTE]
> While the size of our binary is limited to 0x8000 bytes, we can set an arbitrary size for our `.bss` segment. It is still limited to a maximum of `VM_MAX_BSS_LENGTH` = 10485760 bytes = 10 MB, however, this turns out to plenty to ensure that our data segment is `mmap`ed.

We now have the ability to write a 32 bit value into libc's memory. This means that we can hijack libc's GOT, which on the version of libc in use by the challenge (2.38) is still writable! As such, we can use our OOB-write to overwrite the bottom 32 bits of the GOT entry for `strlen` using a specially prepared `CALL` opcode after offsetting the progstack using `ENTER`, redirecting it to point to `system` instead. This works out perfectly, since both functions take a single `char*` argument. Following this, we can pop a shell by simply attempting to print `/bin/sh`, since `printf` will internally invoke `strlen` on the text we want to print.

> [!NOTE]
> Stray invocations of `strlen` won't crash - an invalid command will be executed, causing `system` to error out and return an exit code (usually smaller than 256) to the caller. This means that the caller may read up to 256 bytes past the end of the string, but this almost certainly won't be enough to cause a crash.

> [!NOTE]
> `CALL` will also push the return address onto the progstack, which will clobber some other unrelated GOT entry. This is fine though, since said entry most likely won't be invoked in the short period of time before we pop a shell :)

The final exploit plan looks as follows:
- leak the uninitialized opstack contents, recovering the base address of libc from the leak
- use `ENTER` to offset the progstack pointer into the GOT of libc, near the `strlen` GOT entry
- use `CALL` to invoke an (invalid) system call. This will cause the return address to be pushed onto the progstack (clobbering some unrelated GOT entry), but more importantly, cause the syscall number to be pushed onto the progstack, overwriting the lower 32 bits of the `strlen` GOT entry with the address of `system`.
  - if the address of `system` does not map to a valid syscall number (because of ASLR), we're out of luck, and will have to retry :/
- the syscall will almost certainly be an invalid syscall, however, this does not terminate the program, and only prints a warning. As such execution returns back to the VM interpreter
- use the regular `PRINTF` syscall to print the text `/bin/sh`, which `printf` will pass to `strlen` internally, popping a shell
- profit :)

You can find the full exploit code [here](./q3vm-exploit).

After getting lucky with ASLR, we can get the flag! 🎉
```sh
[+] Opening connection to q3vm.nc.jctf.pro on port 1337: Done
[*] Switching to interactive mode

Bad system call: -1107010225
$ whoami 
whoami: cannot find name for user ID 1002: No such file or directory
$ ls /
bin
flag.txt
jailed
lib
lib64
tmp
usr
$ cat /flag.txt
justCTF{plug1n_c4ll3d_c4ptur3_th3_fl4g}
```