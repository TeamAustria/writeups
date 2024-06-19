# Star

## Description

```
I made my own file manager... Here you have a DEMO version of it.

nc star.nc.jctf.pro 1337
```

Tags: `RE`, `MISC`

`EASY`

## Provided Files

```
- star.tar.gz
```

Which contained the ELF binary `star`.

## Writeup

> [!NOTE]
> Initially `Hannah` and me (`notcat`) were working on this. After some time `berndoJ` and `Xer0` also joined us.

> [!NOTE]
> Jump to [Solution](#solution) if how we got there does not interest you.

This already started a bit weird for a challenge tagged with `RE`, as the reversing challenges I saw up until this point never had an endpoint associated with them. Additionally, the first things we gathered about this challenge did not bolster our confidence:

The provided binary is stripped c++.

Ignoring the binary for now, once connected to the endpoint we were greeted by:

```
JCTF COMMANDER v0.1
1. create file
2. rename file
3. print file
4. delete file
5. edit file
0. exit
>
```

Where the options all do what one would expect from them.

We did have a look around the binary, including decrypting the strings used in it at a later time (credit to `berndoJ`), but in the end the only relevant information we did not get another way as well was that there are options which are not displayed. This was a hunch coming from the 9 really similar blocks of 3 function calls each in `main` before the interactive loop starts:

```c++
// ...
                    /* try { // try from 001048ff to 00104903 has its CatchHandler @ 00104a6e */
  FUN_0010a300(local_b0);
  FUN_0010b2f0(local_68,local_b0);
  FUN_0010b2c0(local_b0);
                    /* try { // try from 00104924 to 00104928 has its CatchHandler @ 00104ada */
  FUN_0010a440(local_a8);
  FUN_0010b3c0(local_60,local_a8);
  FUN_0010b390(local_a8);

    // ...
    // repeat in similar fashion 6 times
    // ...

                    /* try { // try from 00104a18 to 00104a1c has its CatchHandler @ 00104a86 */
  FUN_0010aa80(&local_70);
  FUN_0010b7d0(local_28,&local_70);
  FUN_0010b7a0(&local_70);
// ...
```

It seems like an array of function pointers gets created, indexed depending on the user input by the function @`00106ec` and then called by this line at the end of the interactive loop:

```c++
(**(code **)*puVar3)(puVar3);
```

Discovering this gave us access to the commands 6, 7, & 8. Of these both 6 & 8 respond with `not implemented yet`, but 7 prompts for `Input archive name:`

Then using `strace` with the local binary we discovered the exact `tar` command being run. With that we had all the information necessary to arrive at our solution:

### Solution

The hidden option `7` executes the command `/bin/tar cf <archive-name> *`. Where `<archive-name>` is a user provided name with rather limited allowed characters.

User-input filenames when creating files are similarly limited, however the destination parameter when renaming is not.

Specifically, all characters required for option `(a)` from the [tar-gtfobins](https://gtfobins.github.io/gtfobins/tar/#shell) are allowed when renaming.

> Credit to `neverbolt` for the hint to `gtfobins`

The precise steps required are then:

1. create 3 files with arbitrary names
2. rename a file to `--checkpoint=1`
3. rename another file to `--checkpoint-action=exec=sh` (using `sh` instead of `/bin/sh` as slashes are not allowed in filenames)
4. select option `7` and provide a not yet existing filename for the archive
5. have shell access inside directory `/tmp/fs`
6. the flag `justCTF{th3_st4r_1s_sh1n1ng}` is in `/flag.txt`

## Conclusion

The `EASY` difficulty is probably warranted, but the ghidra c++ decompilation did lead to
> `thats hella cursed c++`

being written in our team chat. ;)
