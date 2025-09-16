# sss

Este script implementa una versión de Shamir's Secret Sharing (SSS) sobre el campo finito GF(2⁸), usando el polinomio irreducible x8+x4+x3+x2+1x^8 + x^4 + x^3 + x^2 + 1 (hex 0x11B).

No me pregunten, no se como funciona la interpolacion de Lagrange pero esto resuelve el problema:

```py
import binascii

# 1) Operations in GF(2⁸) with polinomy x⁸ + x⁴ + x³ + x² + 1 (0x11B)
def gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return res

def gf_pow(a: int, exp: int) -> int:
    result = 1
    while exp:
        if exp & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        exp >>= 1
    return result

def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("Not zero inverse in GF(2^8)")
    # a^(2^8-2)
    return gf_pow(a, 0xFE)

def parse_ssss_share(raw_hex: str) -> bytes:
    hs = "".join(raw_hex.strip().split())
    # add 0 in case of odd-length
    if len(hs) % 2:
        hs = "0" + hs
    blob = binascii.unhexlify(hs)
    return blob

# 3) Lagrange interpolation in x=0 for GF(2^8)
def recover_secret(shares: list[tuple[int, bytes]]) -> bytes:
    length = len(shares[0][1])
    secret = bytearray(length)

    for i in range(length):
        acc = 0
        for j, (xj, share_j) in enumerate(shares):
            num = 1
            den = 1
            for k, (xk, _) in enumerate(shares):
                if k == j:
                    continue
                num = gf_mul(num, xk)
                den = gf_mul(den, xk ^ xj)
            lag = gf_mul(num, gf_inv(den))
            acc ^= gf_mul(lag, share_j[i])
        secret[i] = acc

    return bytes(secret)

# === shares ===
P1 = "8010ba0d6ed38ef563074c3ee80a44f7fe680e82015a8d35f7f2245f66ec9c889b4e31a0c3e97bceeb6f28695f7a494918e0ca079677f07fff8eb570c17a4cb1db0477b84e9c68b9f02b21b33850f33bbd18f886b65c1f3bb015ddbe2723e64abfe8595e181d69d3f8ca3b7cc01c875ea25b97ef1e171c4f3f887e5752541270ae461cc610b3eb422c34df84e7b9a567f7933ee4b6969d19273d212a3ee92f8509679a4b40b6823c007e6d5c6241959e86bc8f989754649cd3008bdbb5bf030c9e802adf54d3afce4edef9bb709c7db4c2ac1f96f3e05cd220534b5647f35888e0e3d2435abdb1d7f32413bb630b3e8b0502e774dda8ac2bd4c2623ac433f79bd12"
P2 = "80264e325aa037314746964303cf6fee98d64e1e03d613fb8f327f5241850adbd06e1f959bdb6e5bd35874188e3fa4740a1948befcacb8949350574825ba4519793a6a617048fb2f5bdd9bc3267a61051484ec16e83ff7baaafac81a3aa4fb2077da312ee4f00c705b8f626334ff3045e41f451858988a3549e314f8a70f0879f5a30fbcd5fcc1645575186af8a434876304bb1ebc360533389143f7d918682307736bac713b63338482ef1cf80ac415f213625231ef3d3bdd70f811c8cc7515cf83a74ea25c31264a9a5dbe0615c5959e181bf8effa1698ece11cb5e9c794d381311ba1900f0c550f33b61fd49959d9b4ba73588b14906fddb625bd13f7149a95a"
P3 = "8036f43f3473b9c42441da7debc52b1966be409c028c9ece78c05b0d276996534b202e355832159538375c71d145ed3d12f982b96adb48eb6cdee238e4c009a8a23e1dd93ed49396abf6ba701e2a923ea99c14905e63e8811aef15a41d871d6ac8326870fced65a3a345591ff4e3b71b4644d2f7468f966a71bb698ff6cb198958d5105ac65f2c367a31c4fe1c0d97b09717867a09209e0a1cac64ede1c144d60854f7c7321de22f82ec8470991b57db729feb8aa0eb5ab7081070aa7b33755952238b81f5cf9dc80724a26575d9bba15ae4027e1f9a490acfd25183adb4ca1b62a2ca92c9a2bee2fa27a634b4b26402b298975c509c3f240f344037d1a4e44142b"

shares = [
    (1, parse_ssss_share(P1)),
    (2, parse_ssss_share(P2)),
    (3, parse_ssss_share(P3)),
]

secret = recover_secret(shares)
print("Secret (hex):", secret.hex())
try:
    print("Secret (plaintext):", secret.decode()[::-1])
except UnicodeDecodeError:
    print("No es UTF-8 imprimible")
```

`ctf{d6b72529c6177d8f648ae85f624a24d6f1edce5ca29bd7cc0b888e117a123892}`



