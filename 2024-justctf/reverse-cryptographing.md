# Write-up reverse cryptographing

[justCTF 2024 Teaser](https://2024.justctf.team/) (15.06.2024 - 16.06.2024)

>[!NOTE]
>Category: Cryptography <br>
>Points: 178 <br>
>Author: [CallMeAlasca](https://github.com/CallMeAlasca)

I've tried to write this as beginner-friendly as possible as the solution of this challenge builds on an essential part
of a lot of attacks on block ciphers.

## Challenge

Description: Always remember to remove repeats when concatenating.

### Source Files

As with the other challenges, we are given the entire docker setup but we only need to look at task.py:

```python
#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

flag = os.environ['FLAG'].encode() if 'FLAG' in os.environ else b'justCTF{temporary-reverse-cryptographing-flag}'
iv = get_random_bytes(16)
key = get_random_bytes(16)


def padded(pt):
    pad_len = -len(pt) % 16
    return pt + bytes([pad_len]) * pad_len


while True:
    suffix = bytes.fromhex(input())

    plaintext = flag
    while len(suffix) and len(plaintext) and plaintext[-1] == suffix[0]:
        plaintext = plaintext[:-1]
        suffix = suffix[1:]

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted = cipher.encrypt(padded(plaintext + suffix))

    print(encrypted[-16:].hex())
```

## Solution

### Initial Analysis

First we need to get a good understanding of what is happening, luckily not much:

1. Upon connecting to the server, a key, iv and flag are generated/loaded.
2. we are asked to input a hex string
3. the last letter of the flag is compared to the first letter of the input
    - if they are equal, both are removed
    - this is repeated until they are not equal or one of the strings is empty
4. AES is initialized in CBC mode with the key and iv
5. the remaining input gets appended to the flag
6. the flag+input gets padded
7. the padded flag+input gets encrypted
8. the server returns the last 16 bytes of the encrypted flag+input
9. Back to step 2 until the connection is closed

From this we can conclude, that the challenge is a simple padding oracle. To understand how to exploit it, let's take a
look at how CBC-mode works:
![](./images/CBC_encryption.svg)

Here it is important to recognize, which blocks stay the same and which change depending on our input.

### Finding the flag-length

While we can't determine the flag length exactly, we can check the length of the last block it occupies.
To do this, we first send an empty payload to the server which returns the last block of the encrypted flag + respective
padding. Next we simulate every padding from 1 to 16 bytes and compare it to the initial response of the server. If the
responses match, we know the length of the flag is k * 16 - padding.

```python
def server(input_hex: str):
    conn.sendline(input_hex.encode())
    answer = conn.recvline().decode().strip()
    return answer


conn = remote('reversecryptographing.nc.jctf.pro', 1337)

payload = ''
initial_output = server(payload)
pad_len = 0
for i in range(1, 16):
    payload = bytes([i]) * i
    payload_hex = payload.hex()
    # print(payload)
    if server(payload_hex) == initial_output:
        pad_len = i
        print('Padding length:', i)
        break
flag_len = 16 * 4 - pad_len
```

In our case k = 4, which I determined just by guessing/trial and error.

### Decrypting the flag

Knowing the flag length, we can now go about decrypting the flag.
To do this, we exploit the following server behavior:

e.g. flag = 'justCTF{some-flag}' and payload = '}gaag}'

the server then cancels ag} with our payload and encrypts the resulting string = 'justCTF{some-fl' + 'ag}' + padding

As this is the original flag, the server response equals the initial response. Using this approach, we can bruteforce
the flag byte by byte from back to front.

```python
flag = b''
multiplier = 0
for i in range(len(flag), flag_len):
    multiplier += 2
    for letter in range(0, 256):
        payload = flag + bytes([letter]) * multiplier
        payload_hex = payload.hex()
        output_hex = server(payload_hex)
        if output_hex == initial_output:
            flag += bytes([letter]) * (multiplier // 2)
            print('Flag:', flag)
            multiplier = 0
            break
    print('multiplier:', multiplier)
print(flag[::-1])
```

Note that we multiply the payload by 2 every time we don't find a match. This is because we have to account for double (
or more) characters in the flag. E.g.
``
flag = 'justCTF{flaag}' and payload = '}gaag}' -> 'justCTF{fl' + 'g}' + padding
``
as both a's of our payload cancel with the a's of the flag, resulting in a different string to be encrypted. Now we try 4 a's:
``
flag = 'justCTF{flaag}' and payload = '}gaaaag}' -> 'justCTF{fl' + 'aag}' + padding
``
which results in the same string as the original flag.

### Flag
Running our exploit on the server now, we get the flag:
```
justCTF{y4d_yyyyPP4h_r333bMer_yAwl4__krr4d_5i_yaD_n3w}
```

### Full Exploit
```python
from pwnlib.tubes.remote import remote


def padded(pt):
    pad_len = -len(pt) % 16
    return pt + bytes([pad_len]) * pad_len


def server(input_hex: str):
    conn.sendline(input_hex.encode())
    answer = conn.recvline().decode().strip()
    return answer


def bruteforce():
    payload = ''
    initial_output = server(payload)
    pad_len = 0
    for i in range(1, 16):
        payload = bytes([i]) * i
        payload_hex = payload.hex()
        # print(payload)
        if server(payload_hex) == initial_output:
            pad_len = i
            print('Padding length:', i)
            break
    flag_len = 16 * 4 - pad_len
    # saving partial flags in case sth goes wrong:
    flag = b'' # b'}w3n_Day_i5_d4rrk__4lwAy_reMb333r_h4PPyyyy_d4y{FTCtsuj'
    multiplier = 0
    for i in range(len(flag), flag_len):
        multiplier += 2
        for letter in range(0, 256): # or string.printable
            payload = flag + bytes([letter]) * multiplier + flag[::-1]
            payload_hex = payload.hex()
            output_hex = server(payload_hex)
            if output_hex == initial_output:
                flag += bytes([letter]) * (multiplier // 2)
                print('Flag:', flag)
                multiplier = 0
                break
        print('multiplier:', multiplier)
    return flag[::-1] # reverse the flag for printing


conn = remote('reversecryptographing.nc.jctf.pro', 1337)

print(bruteforce())

print(conn.recv().decode)
conn.close()
```
