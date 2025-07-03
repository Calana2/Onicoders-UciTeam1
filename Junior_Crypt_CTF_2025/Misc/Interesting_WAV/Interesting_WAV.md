# Interesting WAV

El WAV contenia una imagen JPEG dentro:
```
 /bin/binwalk stego.wav

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             RIFF audio data (WAV), PCM, 1 channels, 8000 sample rate
44            0x2C            JPEG image data, JFIF standard 1.01
```
```
dd if=stego.wav of=stego.jpeg skip=44 bs=1
14725+0 records in
14725+0 records out
14725 bytes (15 kB, 14 KiB) copied, 0,0658476 s, 224 kB/s
```

![2025-07-03-104822_629x296_scrot](https://github.com/user-attachments/assets/555b7466-a45c-42d9-a69e-648e0327aecb)

`grodno{WAV_t0_PNG_0r_PNG_t0_WAV}`




