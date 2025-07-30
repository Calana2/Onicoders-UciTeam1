# based64

En la codificacion base64 se usan bits de padding para completar los grupos de 24 bit y luego agrega uno o dos caracters '='. Este reto usa esteganografia basada en usar los bits de padding para ocultar mensajes

En este repositorio se encuentran utilidades para decodificar el mensaje real: https://github.com/FrancoisCapon/Base64SteganographyTools/

```
 Base64SteganographyTools/tools/b64stegano_retrieve.sh based64.txt
Remaining bits (must be empty or only bits zero): 00

Hidden message: wwf{unUs3d_b1ts_3qu4lz_st3g0_fun}
```

`wwf{unUs3d_b1ts_3qu4lz_st3g0_fun}`
