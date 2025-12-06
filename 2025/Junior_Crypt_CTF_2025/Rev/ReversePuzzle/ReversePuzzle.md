# Reverse Puzzle

El programa toma una cadena de entrada e intercala sus caracteres pares e impares. Hace esto 5 veces y compara el resultado con una cadena; la entrada correcta es la flag.

Podemos invertir las operaciones:
```python
def reverse():
    steps=5
    st='789603251257384214725442633'
    for _ in range(steps):
        h = (len(st) + 1) // 2
        pares = st[:h]
        impares = st[h:]
        l = []
        for i in range(h-1):
            l.append(pares[i])
            l.append(impares[i])
        if len(pares) > len(impares):
            l.append(pares[-1])
        st = "".join(l)
    print(st)

reverse()
```

`grodno{774248325798612643250235431}`
