# El angel exterminador

Nos dan un archivo `flag.png.xor`. Hacemos XOR entre los bytes de la cabecera de un archivo PNG y los del archivo y obtenemos la clave parcial:

<img width="1269" height="630" alt="2025-12-06-105718_1366x768_scrot" src="https://github.com/user-attachments/assets/9f567b5e-6842-4e85-bd6d-d1a575187d1c" />

Con este script que usa `file` para validar el tipo de archivo hacemos fuerza bruta para encontrar el resto de la clave:
```py
import itertools
import subprocess, sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} file_command_output")
    exit(0)

INPUT_FILE = "flag.png.xor"
OUTPUT_FILE = "flag.png"

# Clave parcial conocida
KNOWN_KEY = b"UNLP2025"

# Probar bytes de 0 a 255 (más robusto que ASCII imprimible)
BYTE_VALUES = [bytes([i]) for i in range(256)]

def xor_with_key(data, key):
    # XOR con clave periódica
    klen = len(key)
    return bytes([b ^ key[i % klen] for i, b in enumerate(data)])

def file_type(path):
    # Ejecuta `file` y devuelve su salida como texto
    try:
        out = subprocess.check_output(["file", path], stderr=subprocess.STDOUT)
        return out.decode("utf-8", errors="replace").strip()
    except Exception as e:
        return f"error: {e}"

def is_candidate_valid(file_output):
    # Regla del usuario: si contiene ': data' -> NO es correcta
    if ": data" in file_output:
        return False
    if sys.argv[1] in file_output:
        return True
    return False

def main():
    # Leer archivo cifrado
    with open(INPUT_FILE, "rb") as f:
        enc = f.read()

    found_key = None

    # Extender la clave entre 1 y 5 bytes
    for extra_len in range(1, 6):
        print(f"Probando extensión de clave de +{extra_len} byte(s)...")
        # Iterar todas las combinaciones posibles de longitud extra_len
        for combo in itertools.product(BYTE_VALUES, repeat=extra_len):
            candidate_key = KNOWN_KEY + b"".join(combo)
            # Descifrar
            dec = xor_with_key(enc, candidate_key)
            # Guardar el archivo temporalmente para validarlo con `file`
            with open(OUTPUT_FILE, "wb") as out:
                out.write(dec)
            # Validar con `file`
            ft = file_type(OUTPUT_FILE)
            if is_candidate_valid(ft):
                found_key = candidate_key
                print("Clave encontrada:", found_key)
                print("Salida de `file`:", ft)
                # Mantener file_decoded.png como resultado válido y terminar
                return
        print(f"No hubo coincidencias con +{extra_len} byte(s).")

    if not found_key:
        print("No se encontró una clave válida con extensiones de 1 a 5 bytes.")

if __name__ == "__main__":
    main()
```

```
python3 easy_file_xorer.py "PNG image data"
Probando extensión de clave de +1 byte(s)...
Clave encontrada: b'UNLP2025!'
Salida de `file`: flag.png: PNG image data, 300 x 450, 8-bit/color RGB, non-interlaced
```

<img width="1344" height="585" alt="2025-12-06-110515_1344x585_scrot" src="https://github.com/user-attachments/assets/5395bc6f-091b-4df1-8e85-82860d4b785d" />

`UNLP{f4th3r0fsurrealism!}`




