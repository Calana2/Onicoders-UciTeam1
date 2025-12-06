# Elven Knot

Podemos extraer el bytecode de Python con una herramienta como `pyinstxtractor` y luego pasarle **reverse.pyc** a un decompilador de python como el de https://pylingual.io/

En **reverse.py** vemos esto:
```
 DUO = 35
 str_array = 'str(UNO) + str(DUO) + str(TRES)'
 ..........
  looks_like_secret = 'list(map(lambda x: str(int(x) ** 2), str_array))'
 ..........
  some_func = str('Try to use this: \n\n\n   print(.join(secret variable)) and put that in grodno{}')
 ..........
 TRES = 56
```

Siguiendo esas reglas formamos el array con "UNO", "DOS" Y "TRES", aplicamos esa funcion a cada elemento y converimos la lista en un string, esa es la flag.

``` python
str_array = str(124) + str(35) + str(56)
secret = [str(int(x) ** 2) for x in str_array]
secret = "".join(secret)

assert type(secret) == str

print("grodno{" + secret + "}")
```

`grodno{14169252536}`
