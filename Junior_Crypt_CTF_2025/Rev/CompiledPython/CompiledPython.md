# Compiled Python

Podemos extraer el bytecode de Python con una herramienta como `pyinstxtractor` y luego pasarle **main.pyc** a un decompilador de python como el de https://pylingual.io/

El codigo decompilado luce asi:
```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: main.py
# Bytecode version: 3.10.0rc2 (3439)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

from hashlib import sha256
password = 'th1s_1s_n0t_th3_p4ssw0rd_I_sw3ar'
enteredPassword = input('Enter password: ')
flag = 'grodno{' + sha256(enteredPassword.encode()).hexdigest()[:32] + '}'
if len(enteredPassword) == len(password) and enteredPassword == password:
    print('You are right!')
print(flag)
```

```
./main
Enter password: th1s_1s_n0t_th3_p4ssw0rd_I_sw3ar
You are right!
grodno{88ce08dee4f5c6c9a2188d49fd3e9fdd}
```

`grodno{88ce08dee4f5c6c9a2188d49fd3e9fdd}`
