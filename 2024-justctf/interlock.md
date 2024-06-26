# Interlock

## Credits

- Author of this writeup: [Philogic](https://github.com/PhilippSchweinzer) 
- Thanks to [CallMeAlasca](https://github.com/CallMeAlasca) and [kdm](https://github.com/FRoith) who worked with me on this challenge.


## Description

> Move back to times of good old unbreakable protocols

## Writeup

The challenge consisted of a key exchange between Alice and Bob in `task.py` and the player placed in the middle. To make things easier, the player was given a `eve.py` script which already implemented the code to sniff the key exchange of Alice and Bob.

### Crypto

The first step consisted of proving that we are able to MitM Alice and Bob by providing the server with `x1` and `x2`, which are part of the encrypted messages of them. After we receive the first message from Alice, we generate a new pair of public/private keys and use those to answer back to Alice as Bob:

To do so we generated a new set of private and public keys

```python
ske = suite.KEM.generate_private_key()
pke = ske.public_key().public_bytes(
    encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
)
m1e = json.dumps({"x1": fmt(x1), "n1": fmt(n1), "pka": fmt(pke)})
c1e_d = hashes.Hash(hashes.SHA3_256())
c1e_d.update(m1e.encode())
c1e = c1e_d.finalize()

s1e = ske.sign(m1e.encode(), ec.ECDSA(hashes.SHA3_256()))
m1e_sig = json.dumps({"m1": m1e, "s1": fmt(s1e)})

send_bob(conn, fmt(c1e))
send_bob(conn, m1e_sig)
```

Now we wait for the answer from Alice, capture it and use the knowledge of our previously generated key to also spoof the other side of the connection and answer back as Alice.

```python
m2_enc = recv_bob(conn).decode()
m2_enc = json.loads(m2_enc)
encap, ct, pkb = ufmt(m2_enc["encap"]), ufmt(m2_enc["ct"]), ufmt(m2_enc["pkb"])
pkb_k = ec.EllipticCurvePublicKey.from_encoded_point(suite.KEM.CURVE, pkb)
pka_k = ec.EllipticCurvePublicKey.from_encoded_point(suite.KEM.CURVE, pka)
m2 = suite.open_auth(
    encap,
    ske,
    pkb_k,
    info=b"interlock",
    aad=pkb,
    ciphertext=ct,
)
m2 = json.loads(m2)
x2, n2 = ufmt(m2["x2"]), ufmt(m2["n2"])

m2e = json.dumps(
    {"x2": fmt(x2), "pka": fmt(pka), "m1": json.dumps(m1), "n2": fmt(n2)}
)
encape, cte = suite.seal_auth(
    pka_k, ske, info=b"interlock", aad=pke, message=m2e.encode()
)
m2e_enc = json.dumps({"encap": fmt(encape), "ct": fmt(cte), "pkb": fmt(pke)})

send_alice(conn, m2e_enc)
```

In this state we have undermined the connection and distributed our own keys into the system. This way we are able to decrypt/supply both `x1` and `x2` to the challenge server and pass the check. 

Then we noticed that this solution somehow does not seem to work. This happened because both threads of Alice and Bob have track how long the communication between them took. If a limit of 4 seconds is exceeded, the key exchange fails and the challenge resets. The tricky part is, that both threads also sleep for 4 seconds during the communication so no matter how fast we are able to answer and calculate our MitM we are always going to be just a few milliseconds too slow.

### Pwn

The pwn part of the challenge consisted of a binary called `timer`. This was a C++ compiled binary which seemed very hard to reverse. After a while we agreed that reversing `timer` was not necessary and we just focused on its output which consisted of a timestamp every time input was fed into it.

The clue was that the timestamp was always near the end of a year in 1990. This meant, that according to this timer, it was a few minutes until a Leap second occured and an additional second would be added to the year of 1990. Because the Python implementation uses the `timer` binary to track the elapsed time in the threads and Python does not account for this additional Leap second, we are able to gain an additional second of computation for our MitM if we time everything to happen at exactly midnight.

This is possible, because at the beginning of the exchange we are told the current time of the `timer` binary. We then waited until a few seconds before midnight, started the exchange, used our MitM, passed the time check because of the Leap second and got the flag.

## Flag

`justCTF{p3rf3c71y_un6r34k4b13_1f_n0t_71m3_7r4v31s}`