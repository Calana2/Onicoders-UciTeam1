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
