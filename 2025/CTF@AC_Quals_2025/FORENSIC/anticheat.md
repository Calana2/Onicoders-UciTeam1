# anticheat

**No pude resolverlo en el CTF por filtrar los logs por "vgs_*.log" cuando la flag se encontraba cifrada en "vgs_593_812_635.bin".**

Usando [este script](https://www.unknowncheats.me/forum/anti-cheat-bypass/488665-vanguard-log-decryptor.html) y decodificando el base64: `python3 vgs_decryptor.py vgs_593_812_635.bin | base64 -d` se obtiene la flag.

`ctf{8a11dec7958808f0145aa8bb958f2332a53b6c210776adb9264738b9a31f65cf}`
