# Wackattack 2024 writeups

## Counting the Classics
### Details
Difficulty: `Easy`
```
I just learned about CTR, but I don't understand rijndael so I used something else instead
```
**Task author:** *oksenmu*

### Write-up
The following code was provided to us along with two files: `frequecies`, and `output`

```py
import secrets

from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad


BLOCK_SIZE = 10
NONCE = secrets.token_bytes(10)
KEY = secrets.token_bytes(8)+b"\x00"*2
ALPHABET = b"".join(chr(i).encode() for i in range(127))

def vig(pt: bytes, key: bytes):
    return b"".join(chr((p+k)%128).encode() for p, k in zip(pt,key))

def block_encrypt(pt: bytes, i: int):
    new_nonce = long_to_bytes(bytes_to_long(NONCE)+i)
    return strxor(pt, vig(new_nonce, KEY))

def encrypt(pt: bytes):
    if len(pt) % BLOCK_SIZE != 0:
        raise Exception("Plaintext must be divisable with block length")
    ct = b""
    i = 0
    while i < len(pt) // BLOCK_SIZE:
        ct += block_encrypt(pt[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE], i) # Handle current block
        i += 1
    return ct

if __name__ == "__main__":
    with open("Plaintext.txt", "rb") as f:
        data = f.read().strip()
    freq = [0]*128
    for i in data:
        freq[i] += 1
    freq_dict = {chr(i): val for i, val in enumerate(freq) if val != 0}
    pt = pad(data, BLOCK_SIZE)
    ct = encrypt(pt)
    with open("output", "wb") as f:
        data = f.write(ct)
    with open("frequecies", "w") as f:
        data = f.write(f"{freq_dict}")

```

Looking at the code it appears some sort of vigenere cipher is used in the encryption. That's a very promising start! However upon further inspection we find that the real encryption of the plaintext is done with XOR, not vigenere. Vigenere is only used to combine a static key with a nonce value which is incremented for each block.

Luckily the nonce value (`NONCE`) is a 10-byte value which is only incremented by 1 for each block. This means that if the most-significant-byte of the nonce was to change twice it would have to happen after at least `2^73` blocks had been written. We are not dealing with this much ciphertext here, so that is not going to happen.

In fact, a lot of the bytes in the key would not change, and large parts of the ciphertext is therefore encrypted with the exact same key-byte throughout most of the plaintext.

We can use this to find these more persistent key-bytes using frequency analysis. The file `frequecies`, which we where provided with, gives us the precise symbols frequencies in the plaintext. So all we have to do is make sets of ciphertext symbols that have been (assumedly) encrypted with the same key-byte, and make a frequency chart over them. We can then match that frequency information with the frequencies of the plaintext to find the most likely key-byte.

The general idea can be shown more neatly in code. There are a few functions here I have not included, but they do exactly what their names implies. Feel free to ask me for the code if you are unsure of how they could be implemented.

```python
def solve_subset(subset_bytes: bytes) -> (bytes, bytes):
    freq_dict = generate_freq_dict(subset_bytes)
    most_common_symbol = get_most_common_symbol(freq_dict)

    most_likely_key = strxor(
        most_common_symbol[0].encode("utf-8"),
        PLAINTEXT_MOST_COMMON_SYMBOL[0].encode("utf-8")
        )
    
    subset_likely_plaintext = decrypt_bytes_one_key(subset_bytes, most_likely_key)

    return (subset_likely_plaintext, most_likely_key)

for cipher_set_number in range(10):
    set_content = CIPHERTEXT[cipher_set_number::10]
    (set_likely_plaintext, set_likely_key) = solve_subset(set_content)
```

After doing this for all 10 subsets of the ciphertext (keysize is 10), we get some output which in my case looked something like this:
```sh
$ python3 solution.py
{0: b'\x0e', 1: b'r', 2: b'\x1a', 3: b'L', 4: b'r', 5: b'\x17', 6: b'\x1b', 7: b'#', 8: b'Y', 9: b'6'}
b'Title: "L\x0c. Wac\'s I\nnt for ti\x19 Flag"\nP`\x0ft 1: The!8eginning\x0bqMr. Wac v\x19s not yot\x0b typical!\x0eacker.[...]
```
Here I have simply printed the likely keys along with what my current "*plaintext*" looks like. As you can see it is possible to make out some words already. We can use this to start guessing at what the plaintext really is, so that we can calculate the key. Really we only need 1 block of plaintext to find the initial key, and the subsequent keys are all just increments from that key.

In the plaintext output above we can establish that the first 7 bytes are most likely right (`Title: `). Byte 8 is probably also right (`"`), but I decided to not lock that one in just yet. When it comes to these values the less significant the bytes where in the key, the more they would change throughout the ciphertext, and the more  likely our frequency analysis has made some errors when decoding them. Bytes 9 and 10 (`L\x0c`) are assumed to be wrong.

Looking ahead I spotted the part `Wac\'s I\nnt for ti\x19 Flag`. Now `I\nnt` I have no clue what could be just yet, but `ti\x19` is likely to be `the` and `Wac\'s` is likely to be `Wack's` (since the name of the CTF is `wackattack`). So by using XOR on the ciphertext in the position we would like to see (i.e. `h` in `the`) we can guess at a key-byte for that position.

I implemented this in a dictionary of hard-coded subset keys, so that my solution would skip frequency analysis of those bytes and just use the provided key instead. This yielded the following:
```sh
$ python3 solution.py 
{0: b'\x0e', 1: b'r', 2: b'\x1a', 3: b'L', 4: b'r', 5: b'\x17', 6: b'\x1b', 7: b'#', 8: b'X', 9: b'6'}
b'Title: "M\x0c. Wac\'s H\nnt for th\x19 Flag"\nPa\x0ft 1: The 8eginning\nqMr. Wac w\x19s not you\x0b typical \x0eacker.
```

Now things are looking even better, so I repeated this tactic a few times and ended up getting the entire initial key used for the encryption. I then decrypted the ciphertext one block at a time, ensuring I incremented the key by 1 for every block.

In the end I ended up with a slightly mangled plaintext, but I could read most of the flag. So I manually fixed up the parts I saw was wrong, and submitted the flag in it's simplest lowercase form.

<details>
<summary> Flag </summary>
<pre> <b> wack{not_any_more_secure_than_viginere}</b> </pre>
</details>
