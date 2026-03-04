# Byte-Underflow

The image was one digit left from being a valid jpeg:
```
 xxd flag.jpg|head
00000000: fed7 fee0 ffbb 4477 6865 ffff 4848 29ff  ......Dwhe..HH).
00000010: 07ff ffff 05ff 1100 02ff 00ff ffff 00ff  ................
00000020: ffff 1900 04ff 00ff ffff 55ff ffff 1a00  ..........U.....
00000030: 04ff 00ff ffff 5dff ffff 2700 02ff 00ff  ......]...'.....
00000040: ffff 01ff ffff 1201 02ff 00ff ffff 00ff  ................
00000050: ffff 6886 03ff 00ff ffff 65ff ffff ffff  ..h.......e.....
00000060: ffff 5fff ffff 00ff ffff 5fff ffff 00ff  .._......._.....
00000070: ffff 05ff ff8f 06ff 03ff ffff 2f31 302f  ............/10/
00000080: 0090 06ff 03ff ffff 0001 02ff ff9f 06ff  ................
00000090: 03ff ffff 2f30 2f2f 009f 02ff 00ff ffff  ..../0//........
```

```py
def shift(file):
    with open(file,"rb") as f:
        data = bytearray(f.read())
        for i in range(len(data)):
            data[i] = (data[i] + 1) & 0xff
    open(f"{file}_shifted",'wb+').write(data)

shift("flag.jpg")
```

`byteshift{wow_can_you_bel1eve_that_1_byt3_w4s_shifted_2_times}`



