# backdoored

Input `/dev/shm/backdr` to access to the key validator.

The user input for the key is divided in groups of 2 letters. Each group of 2 letters is hashed with SHA256. The first 4 characters of each hash is transformed with a xor and a substraction and then  compared to a list of 4 characters. If every group of 4 characters match its won, the user input is the flag.

```py
import hashlib
import itertools

expected = [
    0x68CF, 0xAAB5, 0x0021, 0x6237,
    0x730A, 0x2451, 0x84DB, 0x1D5D,
    0x95FA, 0x8B04, 0x5778, 0x9546,
    0x8606, 0xD0A3, 0x6237, 0x11D4
]
vals = [((t ^ 0x2e) + 0x32) & 0xffff for t in expected]

charset = [chr(c) for c in range(0x20, 0x7f)]

result_pairs = [''] * 16

for i, target in enumerate(vals):
    found = False

    for a, b in itertools.product(charset, repeat=2):
        chunk = (a + b).encode('ascii')
        digest = hashlib.sha256(chunk).digest()
        if digest[:2] == target.to_bytes(2, 'big'):
            result_pairs[i] = a + b
            print(f"{a + b}")
            found = True
            break
    if not found:
        raise RuntimeError(f"Error, value not found: {i}")

input_reconstruido = ''.join(result_pairs)
print("Key:", input_reconstruido)

```
