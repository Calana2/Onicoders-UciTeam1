# Python PRNG Hack

El programa genera numeros aleatorios con el modulo `random` de Python.

Este modulo usa el algoritmo **Mersene Twister**, cuyo siguiente numero se puede predecir teniendo la secuencia de los anteriores 624 numeros (esto revela su estado interno)

![2025-07-04-042417_708x154_scrot](https://github.com/user-attachments/assets/1c3c7493-eb8b-4f15-ae73-bb8fcbaa4abb)

`randcrack` es una libreria que se usa para predecir numeros aleatorios de Python sabiendo el estado interno del algoritmo.

```python
from pwn import *
from randcrack import RandCrack

def exploit():
    rc = RandCrack()
    r = remote("ctf.mf.grsu.by",9043)

    # Collecting 624 numbers
    print("Collecting numbers...")
    for i in range(624):
        r.sendlineafter(b'> ', b'1')
        line = r.recvline().decode().strip()
        num = int(line.split(': ')[1])
        rc.submit(num)
        if (i+1) % 100 == 0:
            print(f"{i+1}/624...")

    # Predecir y enviar
    predicted = rc.predict_getrandbits(32)
    print(f"Sending prediction: {predicted}")

    r.sendlineafter(b'> ', b'2')
    r.sendlineafter('Ваше число: '.encode(), str(predicted).encode())

    print(r.recvall().decode())
    r.close()

exploit()

```
