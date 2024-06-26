Duality
=======

[justCTF 2024 Teaser](https://2024.justctf.team/) (15.06.2024 - 16.06.2024)

>[!NOTE]
>Category: Crypto <br>
>Points: 237 (36 Solves)<br>
>Author: [berndoJ](https://github.com/berndoJ)

We were given the following prompt:
>GMAC is too fragile, so I made a nonce-based alternative to CW hashes. I use
>HMAC, so nothing can go wrong. But I am not sure how to use nonces with HMAC...

Together with a tarball containing the challenge's remote Python script:

<details>

```python
#!/usr/bin/env python3


import json
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

import sys

from server_config import hint, flag

def integer_to_base(n, base):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(n % base)
        n //= base
    return digits[::-1]

def write(data: dict):
    print(json.dumps(data))

def read():
    try:
        return json.loads(input())
    except EOFError:
        exit(0)

class CustomHMAC:
    def __init__(self):
        self.prime = 22193
        self.key_1, self.key_2 = self.generate_keys()
        
    def generate_keys(self):
        key1 = AESGCM.generate_key(bit_length=128)
        key2 = secrets.randbelow(self.prime)
        return key1, key2

    def poly_hash(self, key, message_array) -> int:
        assert len(message_array) <= 5
        hash = 1
        # Compute the polynomial hash using Horner's method
        for i in range(len(message_array)):
            hash = (hash * key + message_array[i]) % self.prime
        return hash

    def compute_custom_mac(self, nonce, msg_array):
        poly_hash = self.poly_hash(self.key_2, msg_array)
        k_intermediary = hmac.new(nonce, self.key_1, hashlib.sha256).digest()
        hmac_result = hmac.new(k_intermediary, poly_hash.to_bytes((poly_hash.bit_length() + 7) // 8, byteorder='big'), hashlib.sha256).digest()
        return hmac_result
    
    def check_collision(self, nonce_1, msg_1, nonce_2, msg_2, guess_key_2):
        # Enforcing length on one of the nonces
        if len(nonce_1) < 65:
            return 'Invalid'

        msg_array_1 = integer_to_base(int.from_bytes(msg_1, 'big'), self.prime)
        msg_array_2 = integer_to_base(int.from_bytes(msg_2, 'big'), self.prime)
        
        if nonce_1 != nonce_2 and msg_array_1 != msg_array_2:
            mac_1 = self.compute_custom_mac(nonce_1, msg_array_1)
            mac_2 = self.compute_custom_mac(nonce_2, msg_array_2)
            if mac_1 == mac_2:
                if guess_key_2 == self.key_2:
                    return f'flag: {flag}'
                else:
                    return f'hint: {hint}'
        return 'Invalid'

WELCOME="""
Your friend implemented a custom MAC scheme and bets you $100 that it's secure.
You take him up on the bet.
Can you prove him wrong?

The way to prove that you've broken his MAC scheme is by performing a collision attack.
Create two (nonce, msg) pairs that have the same MAC tag.

Oh, and also, recover one of the keys used to generate the MAC tags.
"""

def serve():
    write({'message': WELCOME})
    hmac = CustomHMAC()

    while True:
        try: 
            msg = read()

            if msg['method'] == 'submit':
                msg['nonce_1'] = bytes.fromhex(msg['nonce_1'])
                msg['nonce_2'] = bytes.fromhex(msg['nonce_2'])
                msg['msg_1'] = bytes.fromhex(msg['msg_1'])
                msg['msg_2'] = bytes.fromhex(msg['msg_2'])
                msg['guess_key_2'] = int(msg['guess_key_2'])
                result = hmac.check_collision(msg['nonce_1'], msg['msg_1'], msg['nonce_2'], msg['msg_2'], msg['guess_key_2'])
                write({'message': result})
                
        except Exception as e:
            write({'error': repr(e)})

if __name__ == '__main__':
    serve()

```

</details>

## Overview

The challenge itself implements a custom hashing algorithm based on polynomials
in galois fields.

Specifically, the core of the hashing algorithm is the `poly_hash` function

```python
def poly_hash(self, key, message_array) -> int:
    assert len(message_array) <= 5
    hash = 1
    # Compute the polynomial hash using Horner's method
    for i in range(len(message_array)):
        hash = (hash * key + message_array[i]) % self.prime
    return hash
```

which takes a key $k \in \textrm{GF}(p)$ and message block $\mathbf{m} \in \textrm{GF}(p)^N$, $\mathbf{m} = \{m_i : i \in \{0, 1, 2, ..., N\}\}$.

$$P(k, \mathbf{m}) = k^N + \sum_{i=0}^{N} m_i k^{N-1-i}$$

The cusom MAC $h(n, \mathbf{m})$ with nonce $n$ and message $\mathbf{m}$ is then
calculated using fixed keys $k_1$ and $k_2$ via

$$h(n, \mathbf{m}) = H(H(n, k_1), P(k_2, \mathbf{m}))$$

with $H(k, m)$ being the standard HMAC implementation.

To obtain the flag, we must find a set of nonce and message block pairs that
produce a hash collision and extract the key $k_2$ in addition to that. However,
only producing a collision without guessing $k_2$ provides a hint, so we can
build a collision oracle without knowing $k_2$.

```python
def check_collision(self, nonce_1, msg_1, nonce_2, msg_2, guess_key_2):
    # Enforcing length on one of the nonces
    if len(nonce_1) < 65:
        return 'Invalid'

    msg_array_1 = integer_to_base(int.from_bytes(msg_1, 'big'), self.prime)
    msg_array_2 = integer_to_base(int.from_bytes(msg_2, 'big'), self.prime)
    
    if nonce_1 != nonce_2 and msg_array_1 != msg_array_2:
        mac_1 = self.compute_custom_mac(nonce_1, msg_array_1)
        mac_2 = self.compute_custom_mac(nonce_2, msg_array_2)
        if mac_1 == mac_2:
            if guess_key_2 == self.key_2:
                return f'flag: {flag}'
            else:
                return f'hint: {hint}'
    return 'Invalid'
```

## General Concept of Exploitation

Since we need to provide different messages and different nonces, with one
nonce being at most 64 bytes long, we first need a way to generate an HMAC
collision using the fixed key $k_2$ and given nonce to have `k_intermediary`
fixed in the `compute_custom_mac` function. This is required to reduce the
collision problem to finding a collision for only the polynomial $P(k, \mathbf{m})$,
which is much simpler.

To create the HMAC "collision", we can use the fact that if you provide the
HMAC function with a key that is larger than 64 bytes, it first calculates the
SHA256 of the given key and then uses the result as the nonce. Thus, we can just
use 65 `a`s as the first nonce and the SHA256 hash of the 65 `a`s as the second
nonce to produce a "collision" from the HMAC output. This is no real hash
collision but rather an implementation artefact that was not considered during
the implementation of the custom hash.

Now, we set one message to be $\mathbf{m}_1 = \mathbf{0}$, which results in

$$P(k_2, \mathbf{m}_1) = k_2$$

By then setting the second message to be $\mathbf{m}_2 = (\ell, 0)^\top$, which
the block representation for the number $\ell p$, we observe the output to be

$$P(k_2, \mathbf{m}_2) = (k_2 + \ell) k_2$$

A collision occurs when the condition

$$k_2 = (k_2 + \ell) k_2 \quad \Leftrightarrow \quad 0 = (k_2 + \ell - 1) k_2$$

holds true for a given $\ell$. Since the prime used $p = 22193$ is very small,
we can just exhaustively search for the collision using the remote as an oracle,
since it prints the hint when the collision occurs.

Then, when we know which $\ell$ to use to generate the collision, we can simply
solve for the roots of the polynomial

$$(x + \ell - 1) x$$

w.r.t. $x$ to obtain the key $k_2$.

We submit the result for $k_2$ again together with the colliding nonce/message
pair and get the flag back from the remote:

```
justCTF{4bcd3fgh1jkl2mno3pqr4stuv5wxyz}
```

## Exploit

The exploit was developed in Python using `pwntools` for interacting with the
remote / local Python script and `sagemath` for working with polynomials over
$GF(p)$.

<details>

```python
#!/usr/bin/env python3

from sage.all import *
from pwn import *
import json
from Crypto.Util.number import long_to_bytes

# Helper lambda macros
linfo = lambda x: log.info(x)
lwarn = lambda x: log.warn(x)
lerror = lambda x: log.error(x)
lprog = lambda x: log.progress(x)

byt = lambda x: x if isinstance(x, bytes) else x.encode() if isinstance(x, str) else repr(x).encode()

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

# remote / local target
if args.REMOTE:
    t = remote("duality.nc.jctf.pro", 1337)
else:
    t = process(["python3", "./polyhash.py"])

def guess(nonce_1, nonce_2, msg_1, msg_2, guess_key_2):
    payload = guess_payload(nonce_1, nonce_2, msg_1, msg_2, guess_key_2)
    sl(payload)
    return json.loads(rl().decode())

def guess_payload(nonce_1, nonce_2, msg_1, msg_2, guess_key_2):
    pl = {
        "method": "submit",
        "nonce_1": nonce_1.hex(),
        "nonce_2": nonce_2.hex(),
        "msg_1": msg_1.hex(),
        "msg_2": msg_2.hex(),
        "guess_key_2": guess_key_2
    }
    return json.dumps(pl).encode()

rl() # Read start
P = 22193
F = GF(P)
PR = PolynomialRing(F, "x")
x = PR.gen()
BLOCKLEN = 128 # Number of guesses to submit in one batch.

# Nonce 1 and nonce 2 generate a "hash collision" for k_intermediary, as hmac
# uses sha256(nonce) if nonce is larger than 64 bytes
nonce_1 = b"a"*65
nonce_2 = hashlib.sha256(nonce_1).digest()

pls = [] # Payloads
res = [] # Results from payloads
for i in range(P):
    pl = guess_payload(nonce_1, nonce_2, long_to_bytes(i*P), long_to_bytes(0), 1)
    pls.append(pl)

lp_send = lprog("Sending guess payloads to remote")
for i in range(0, len(pls), BLOCKLEN):
    do_pls = pls[i:i+BLOCKLEN]
    lp_send.status(f"{i+1} / {len(pls)}...")
    for p in do_pls:
        t.sendline(p)
    for _ in range(len(do_pls)):
        res.append(t.recvline())
lp_send.success("Guesses processed.")

linfo("Now decoding answers from guesses...")

for i, r in enumerate(res):
    jr = json.loads(r.decode())

    # Find the one message with the hint to figure out correct msg guess.
    if jr["message"] != "Invalid":
        poly = (x + F(i) - 1) * x
        r = poly.roots()
        key = max([x[0] for x in r])
        linfo(f"{key = }")
        linfo(f"{jr = }")

        # Send guess with key to server to retrieve the flag.
        resp = guess(nonce_1, nonce_2, long_to_bytes(i*P), long_to_bytes(0), int(key))
        print(resp["message"])
        exit()
```

</details>