# sigdance

El programa convierte la entrada a `unsigned long` y la valida con la funcion `verify`:
```c
  while (fgets(buf, sizeof(buf), stdin)) {
    char *e = buf;
    uint32_t prov = strtoul(buf, &e, 0);
    int ok = verify(prov, (uint32_t)A, (uint32_t)U, PID);
    if (ok) {
      const char *f = getenv("FLAG");
      if (!f)
        f = "FLAG{missing}";
      puts(f);
      dlclose(h);
      return 0;
    } else {
      puts("nope");
      fflush(stdout);
    }
  }
```

```c
#include <stdint.h>

int verify(uint32_t provided, uint32_t ac, uint32_t uc, uint32_t pid) {
  uint32_t token = ((ac << 16) ^ (uc << 8) ^ (pid & 255u));
  return provided == token;
}
```

La validacion depende de `ac` , `dc` y del byte menos significativo del `pid`.

El byte menos significativo del `pid` nos lo comparten:
```c
uint32_t PID = (uint32_t)getpid();
  srand((unsigned)time(NULL) ^ PID ^ A ^ U);
  printf("Hello from pid8 = %u\n", (unsigned)(PID & 255u));
  fflush(stdout);
```

`ac` y `dc` son el contenido de las variables locales `A` y `U` que son alteradas en la funcion `compute_counts`.

## Analizando compute_counts
`int sigemptyset(sigset_t *set);` inicializa un conjunto de señales vacio, con todas las señales excluidas del conjunto.

`int sigaddset(sigset_t *set, int signum);` añade una señal al conjunto.

`int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset);` desbloquea las señales del conjunto.

Este bloque asegura que el hilo actual pueda recibir `SIGALRM` y `SIGUSR1`
```c 
  sigset_t unb;
  sigemptyset(&unb);
  sigaddset(&unb, SIGALRM);
  sigaddset(&unb, SIGUSR1);
  pthread_sigmask(SIG_UNBLOCK, &unb, NULL);
```


`void *memset(void s[.n], int c, size_t n);` llena los primeros `n` bytes de la direccion apuntada por `s` con la constante `c`.
 
`int sigaction(int signum, const struct sigaction *_Nullable restrict act, struct sigaction *_Nullable restrict oldact);` registra el manejador `act` para la señal `signum`. 
 
La bandera `SA_RESTART` le dice al sistema operativo: “Si esta señal interrumpe una llamada al sistema (como read(), write(), wait()), reiníciala automáticamente en lugar de devolver un error.”

En este bloque se inicializan dos manejadores de señal, que se reinician si interrumpen un cambio de contexto y que usan las funciones `h_alrm` en caso de un `SIGALARM` y `h_usr1` en caso de un `SIGUSR1` respectivamente.
```c
  struct sigaction sa1;
  memset(&sa1, 0, sizeof(sa1));
  sigemptyset(&sa1.sa_mask);
  sa1.sa_flags = SA_RESTART;
  sa1.sa_handler = h_alrm;
  sigaction(SIGALRM, &sa1, NULL);
  struct sigaction sa2;
  memset(&sa2, 0, sizeof(sa2));
  sigemptyset(&sa2.sa_mask);
  sa2.sa_flags = SA_RESTART;
  sa2.sa_handler = h_usr1;
  sigaction(SIGUSR1, &sa2, NULL);
```

Los manejadores son simples contadores que aumentan `ac` y `uc`:
``` c
static void h_alrm(int s) {
  (void)s;
  ac++;
}
static void h_usr1(int s) {
  (void)s;
  uc++;
}
```

`int setitimer(int which, const struct itimerval *restrict new_value, struct itimerval *_Nullable restrict old_value);` prepara valores para preparar un temporizador.

Este bloque configura un temporizador de alta precisión que dispara la señal SIGALRM cada 7 milisegundos:
```c
struct itimerval it;
it.it_value.tv_sec = 0;
it.it_value.tv_usec = 7000;
it.it_interval.tv_sec = 0;
it.it_interval.tv_usec = 7000;
setitimer(ITIMER_REAL, &it, NULL);
```

Este bloque crea un nuevo hilo (t) que ejecutará la función `th`, pasándole como argumento el PID del proceso actual:
```c
  pthread_t t;
  pid_t me = getpid();
  pthread_create(&t, NULL, th, &me);
```

`th` duerme 5 milisegundos entre cada iteraccion y envia la señal `SIGUSR1` 13 veces:
```c
static void *th(void *arg) {
  pid_t pid = *(pid_t *)arg;
  struct timespec ts = {0, 5000000};
  for (int i = 0; i < 13; i++) {
    nanosleep(&ts, NULL);
    kill(pid, SIGUSR1);
  }
  return NULL;
}
```

Este bloque hace que el hilo principal duerma por 777 milisegundos, luego desactiva el temporizador y espera a que el hilo termine su ejecucion:
```c
  struct timespec s = {0, 777000000};
  nanosleep(&s, NULL);
  setitimer(ITIMER_REAL, &(struct itimerval){0}, NULL);
  pthread_join(t, NULL)
```

En resumen `uc=13` siempre y `ac=11` aproximadamente. 

Bueno, deberia ser asi pero en mis pruebas era `ac=0` siempre. Una posible explicacion puede ser [esta](https://stackoverflow.com/questions/64217976/sigalrm-in-c-does-not-executing-in-the-handler).

<img width="736" height="265" alt="2025-09-16-175807_736x265_scrot" src="https://github.com/user-attachments/assets/fa7d70d5-4271-43d8-b79a-78747f5f5322" />

### Exploit
```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./sigdance_bin")
#libc = ELF("./")
#ld = ELF("./")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
break main
'''

domain= "ctf.ac.upt.ro"
port = 9306

def start():
    if args.REMOTE:
        return remote(domain, port)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])
r = start()

#========= exploit here ===================

r.recvuntil(b"= ")
pid_low = int(r.recvline().strip())
r.info(f"PID low byte grabbed: {pid_low}")
success = False

# Brueforce ac and dc
uc = 13
for ac in range(0, 11):
    if success == True:
        break
    token = (ac << 16) ^ (uc << 8) ^ pid_low
    r.sendline(str(token).encode())
    line = r.recvline().strip()
    if b"nope" not in line:
       print("Success!")
       print(line)
       success = True
       break
```

`ctf{cbc4e1be639219dad8912bb764b566200023e15152635eef87be047c41bd995a}`








