Author: 0x6fe1be2

Version 19-06-24

# [justCTF 2024 teaser](https://ctftime.org/event/2342) (15.06-16.06)

## Wild West
Category: PPC

Points: 355 (11 Solves)

Teammates: Aryt3, Jones, ian

> You have to help. The year is 1886, and the Wild West is booming with opportunity. Towns spring up overnight, driven by gold rushes, cattle drives, and, most recently, a string of casinos promising fortunes to anyone daring enough to try their luck. These establishments, from the bustling streets of Deadwood to the dusty corners of Tombstone, seem to have made a critical error in their game designs. The odds are shockingly favorable to the players. In fact, the expected outcomes are positive, meaning folks have a better chance of winning than losing.
>
> But there's more to this story than meets the eye. Some say the casino owners, usually shrewd and calculating, couldn't have made such a blunder. Rumors spread that these so-called "mistakes" might have more sinister roots. Perhaps the casinos are part of a bigger scheme, aiming to lure people in with easy wins before revealing a darker plot. Your task is to navigate through these perilous waters and ensure the townspeople can capitalize on this opportunity without falling into any traps.
>
>As you travel from town to town, your goal is to help the locals maximize their winnings. You must teach them the best strategies, ensure they understand the odds, and prevent them from getting overconfident and losing their hard-earned money. It's not just about the gold; it's about outsmarting the unseen forces at play. Keep your wits about you, trust your instincts, and remember – in the Wild West, things are rarely as they seem. Good luck, partner.
>
>Prepared for you by [Tacet](https://github.com/AdvenamTacet) from Trail of Bits (check out their [publications](https://github.com/trailofbits/publications) and [blog](https://blog.trailofbits.com/))
>
>```bash
>nc wildwest.nc.jctf.pro 1337
> ```
>

### TL;DR

Simple gambling game, with different win rations and probabilities, that can be won using the [Kelly Criterion](https://en.wikipedia.org/wiki/Kelly_criterion)

### Overview

No Files :,\

So, lets connect to the endpoint

```bash
nc wildwest.nc.jctf.pro 1337
```

And we get:

```
NEW CASINO!
Those 300 people don't want to lose even one coin.
Win 80.0% with chance 50.0% or lose 50.0% in every game.
Here is the next citizen who needs your help with {balance} coins.
Game 1 out of 30
Win: 0.8, loss: 0.5, p(win): 0.5, balane: 2976911
```

This basically already tells us everthing we need to know to solve the chalenge, notably, we need to find some way to calculate the amount to bet using the win, loss ratio and the win probability, so basically sth like this

```python  

def ratio(loss, win, p, q):
  # TODO: implement magic ratio
  # gambling is bad kids : )
  return 0
  
prog = lprog('helping')
line = rls()
inp = 'y'

while inp == 'y': 
  ru('Those ')
  cnt = int(ru(' '), 10)
  for x in range(cnt):
    
    ru('out of ')
    games =  int(rls(), 10)
    for i in range(games):
      out = ru('Win: ')
      win = float(ru(',')[:-1])
      ru('loss: ')
      loss = float(ru(',')[:-1])
      ru('p(win): ')
      p = float(ru(',')[:-1])
      q = 1-p
      ru('balane:')
      bet = int(rls(), 10)
      prog.status("%d/%d: %d/%d Win: %f, loss %f, p(win) %f: ratio %d*%f" % (x, cnt, i, games, win, loss, p, bet, ratio(loss, win, p, q)))
      if round == 0 and i > 25:
      sla('bet:', int(bet*ratio(loss, win, p, q)))

  print('continue (y) or print line (s): ')
  
  while (inp := input()) == 's':
    log.info(rls().decode())
```

> Note: I use a lot of alias functions (`rl() -> t.recvline()`), if you want the full list look at the start of the final exploit

As you can guess from my code there are actually multiple rounds (or towns, as they are called). There are 3 rounds (towns) in total

> Note: My teammates also noticed, that some rounds (towns) seem to have certain gimmicks, e.g. the win ration drops to basically zero in the first rounds between game 25 and 30 for each village, but this wasn't needed to solve the challenge.

### Kelly Criterion

Luckily due to my (self diagnosed) youtube addiction I faintly remember watching this video, about gambling using different win probabilties, which is actually really great and I recommend watching if you want to understand why the algorithm works.

[![ The "Just One More" Paradox ](https://i.ytimg.com/vi/_FuuYSM7yOo/maxresdefault.jpg)](https://www.youtube.com/watch?v=_FuuYSM7yOo)

Ok so basically if we have a gambling problem where we have alternating loss and win ratios using alternating win probabilities, we can define a gambling ratio to achive the best possible average median.

> Note: this isn't a magically win against the house function, and only works if the actually odds are favorible (i.e. if you are the house)

So, lets implement kelly and try to win:

```python
def kelly(a, b, p, q):
  """
  param a: loss ratio
  param b: win ratio
  param p: win probability
  param q: loss probability
  """
  return (p/a) - (q/b)
```

Output:

```python
Success!
The player has 7711586444.
Winner!
Median score: 113.28178983566477
Winners score: 0.9333333333333333
Wealth score:  2944.9876621310395
You helped them!
But the town is not wealthy enough...
Wealthy towns: 2
Not enough of wealthy towns...
```

Hmm, sadly sometimes this happens, but just try again, until it works : )

### Final Script
Flag: `justCTF{that_would_never_happen_IRL}`

<details>

```python3
#!/usr/bin/env python3
from pwn import *
import hashlib

GDB_OFF = 0x555555554000
IP = 'wildwest.nc.jctf.pro'
PORT = 1337
BINARY = '/bin/true'
ARGS = []
ENV = {} # os.environ
GDB = f"""
set follow-fork-mode parent

c"""

# context.binary = exe = ELF(BINARY, checksec=False)
# libc = ELF('', checksec=False)
# context.aslr = False

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

def get_target(**kw):
  return remote(IP, PORT)


def pow(prefix, zero_length):
  user_input = 0
  while True:
    combined = prefix + str(user_input)
    hash_value = hashlib.sha256(combined.encode()).hexdigest()
    if hash_value[:zero_length] == "0" * zero_length:
      sl(user_input)
      return
    user_input += 1

def ratio(a, b, p, q):
  """
  param a: loss for lose
  param b: win for lose
  param p: win probability
  param q: los probability
  """
  return (p/a) - (q/b)

t = get_target()

ru('prefix: ')
prefix = rls().decode()
ru('zero_length: ')
zero_length = int(rls(), 10)

pow(prefix, zero_length)


prog = lprog('helping')
line = rls()
inp = 'y'
rnds = 1
while inp == 'y': 
  ru('Those ')
  cnt = int(ru(' '), 10)
  for x in range(cnt):
    
    ru('out of ')
    games =  int(rls(), 10)
    for i in range(games):
      out = ru('Win: ')
      win = float(ru(',')[:-1])
      ru('loss: ')
      loss = float(ru(',')[:-1])
      ru('p(win): ')
      p = float(ru(',')[:-1])
      q = 1-p
      ru('balane:')
      bet = int(rls(), 10)
      prog.status("%d/%d: %d/%d Win: %f, loss %f, p(win) %f: ratio %d*%f" % (x, cnt, i, games, win, loss, p, bet, ratio(loss, win, p, q)))
      if round == 0 and i > 25:
      sla('bet:', int(bet*ratio(loss, win, p, q)))

  rnds += 1
  inp = input()
  
  while inp == 's':
    log.info(rls().decode())
    inp = input()
  

it() # or t.interactive()

```


</details>