# Unknown Traffic 2

Unos paquetes contenian "CHUNK_" en sus datos, con contenido en base64. Si aplicamos conversiones como ` strings traffic.pcap | grep CHUNK | sort | sed -E 's/^CHUNK_[0-9]+://' | tr -d '\n' | base64 -d  > result` obtenemos en result una imagen png con un codigo QR.

Lo escaneamos para obtener la flag:

<img width="638" height="661" alt="2025-09-16-100559_638x661_scrot" src="https://github.com/user-attachments/assets/bead1359-2ca0-40e5-9699-9d6a94cb7872" />

`ctf{da8978b239f7e78370c36501ee6a0458e7c4dd870463e44ca6f9b949549ebf1b}`
