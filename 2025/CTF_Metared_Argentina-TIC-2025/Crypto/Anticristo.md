# Anticristo

```
This exercise has 3 levels. In the first level I give you several plaintexts and ciphertexts and you must decrypt level 2 to continue:


How are you?: 040e0553371d0b740b06104d

How old are you?: 040e055339030a74131b0052350e074c

Plaintext: 1c0d131a381b0b2c06

You already understood where it goes: 150e075337031c31130d1c52390f1616241c1a3b1d0d45052404001676061a741506000173

Last example: 00000107760a16351f190917


Now decrypt level 2:

02081116762501365c492b17341548795c230f260149331d224126013f0a1c6e520c524a29521742640d5b35105e54402d07134a675d5d65450c014a2d6b3e12240e4e1700060306764117446e0a5d31425907472d024410640c0f65105e6f3e2d41041a320e4e3101490717200d1349760a596c175f06437b00174a35595a61410804112a534347640a0837435b5d462a6b371f761f0f3000000b1d764117166e5c5861430a041475564545675e0c674b586f372041150137014e3c1d1d001e6c030717371f0b2706485f5229044a40605a5e36100a5d477b584612340e0d35445c51422d534a15600d5f61135d5c107b07434237585635400d6f78020804163a4f5d6e520c504a7a531643350e5937415d514675581610655e5860470a004a2d501143370c5c6d455d5c432959174a665b5c60470a5c172f531447350c08304a5b5c4628044710625d5961160b01162d534147300a0830135b5c4728051616375f5b62410a5214785214456065
```

Si hacemos XOR entre cada texto plano y su respectivo texto cifrado obtenemos una clave XOR repetida:

<img width="1344" height="585" alt="2025-12-06-103439_1366x768_scrot" src="https://github.com/user-attachments/assets/52eaff22-a426-4bcf-bbbd-8503119e4977" />

<img width="1346" height="578" alt="2025-12-06-103510_1366x768_scrot" src="https://github.com/user-attachments/assets/c3e26e06-af35-4acb-9bf2-b818852ab846" />

Para el nivel 3 es necesario analizar que hacer XOR esta vez entre el texto plano y el texto cifrado vemos que:
- Los dos primeros bytes son fijos: `ct[i] = pt[i] ^ IV[i]`
- Tercer y cuarto byte de la clave son iguales al primer y segundo byte del texto plano respectivamente: `ct[i] = pt[i] ^ pt[i-2]`

<img width="1298" height="586" alt="2025-12-06-103630_1366x768_scrot" src="https://github.com/user-attachments/assets/349d9c77-7148-4654-ae7c-2d8d6cc5b441" />

<img width="1341" height="580" alt="2025-12-06-103606_1366x768_scrot" src="https://github.com/user-attachments/assets/0b33e4d2-8848-48aa-ba2a-ad7b7044a78d" />

Los siguientes bytes cifrados siguen la fórmula `ct[i] = pt[i] ^ pt[i-2] ^ ct[i-4]`.

```py
cipher = bytes.fromhex("e5862d0ca7c344499dc31645ce8a1c0ac297491e8e904245c9ec2f4ccfd8294de5c4275dbdda234fefda295dddea0563c7f43f66")
pt = []
IV = [0xab,0xef]

def atbash(b):
    if 65 <= b <= 90:
        return 90 - (b - 65)
    if 97 <= b <= 122:
        return 122 - (b - 97)
    return b


for i in range(len(cipher)):
    if i <= 1:
        byte = cipher[i] ^ IV[i]
    elif i  == 2:
        byte = cipher[i] ^ pt[0] 
    elif i  == 3:
        byte = cipher[i] ^ pt[1] 
    else:
        byte = cipher[i] ^ pt[i-2] ^ cipher[i-4]
    pt.append(byte)

print(bytes(pt).decode('ascii',errors="ignore"))
```

```
python3 s.py
Nice! Here is your flag: FMOK{Mzgfiv1h5zgzmh_XsfixS}
```

Decodificamos el cifrado de Atbash y obtenemos la flag: ` UNLP{Nature1s5atans_ChurcH}`
