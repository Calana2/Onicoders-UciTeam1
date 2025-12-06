# More Than A Warm-Up

El hash que se espera coincide parcialmente con esta palabra:

![2025-07-04-045444_1095x429_scrot](https://github.com/user-attachments/assets/a803df6e-8513-4e7b-8b11-5a9de4c6302e)

```
 ./MoreThanAWarmUp.exe Filitoni2
You are right! But flag isn't here :(
```

La logica de la flag real nunca es llamada. Se encuentra en la funcion `maybeGetFlag`.

El flujo de operaciones que se debe realizar con la contraseña está en ella:
``` C

/* WARNING: Unknown calling convention -- yet parameter stora ge is locked */
/* maybeGetFlag() */

void maybeGetFlag(void)

{
  char *current_char;
  byte *first_char_of_md5_password;
  ulong maybeTheFlag_len;
  ostream *this;
  ulong counter;
  long in_FS_OFFSET;
  allocator local_bd;
  int counter_bc;
  allocator *local_b8;
  allocator *local_b0;
  string final_FLAG [32];
  string local_88 [32];
  string single_char_str [32];
  string local_48_password! [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  md5(local_48_password!);
  std::string::operator=((string *)maybeTheFlag[abi:cxx11],local _48_password!);
  std::string::~string(local_48_password!);
  local_b8 = &local_bd;
                    /* try { // try from 001036c7 to 001036cb has its C atchHandler @ 001038a8 */
  std::string::string<>(final_FLAG,"",&local_bd);
  std::__new_allocator<char>::~__new_allocator((__new_allocat or<char> *)&local_bd);
  counter_bc = 0;
  while( true ) {
    counter = (ulong)counter_bc;
    maybeTheFlag_len = std::string::length((string *)maybeTheFl ag[abi:cxx11]);
    if (maybeTheFlag_len <= counter) break;
    local_b0 = &local_bd;
                    /* try { // try from 00103710 to 00103732 has its C atchHandler @ 001038fc */
    current_char = (char *)std::string::operator[]
                                     ((string *)maybeTheFlag[abi:cxx11],(lon g)counter_bc);
    std::string::string<>(single_char_str,1,*current_char,&local_ bd);
                    /* try { // try from 00103741 to 00103745 has its C atchHandler @ 001038eb */
    md5(local_48_password!,(char *)single_char_str);
                    /* try { // try from 00103752 to 0010377a has its C atchHandler @ 001038da */
    first_char_of_md5_password = (byte *)std::string::operator[]( local_48_password!,0);
    std::string::push_back(final_FLAG,(byte)counter_bc ^ *first_c har_of_md5_password & 0x7b);
    std::string::~string(local_48_password!);
    std::string::~string(single_char_str);
    std::__new_allocator<char>::~__new_allocator((__new_alloca tor<char> *)&local_bd);
    counter_bc = counter_bc + 1;
  }
                    /* try { // try from 001037e1 to 001037e5 has its C atchHandler @ 00103933 */
  sha256((int)local_88,final_FLAG);
                    /* try { // try from 001037fb to 001037ff has its Cat chHandler @ 00103922 */
  std::operator+(single_char_str,"grodno{",local_88);
                    /* try { // try from 00103815 to 00103819 has its C atchHandler @ 00103911 */
  std::operator+(local_48_password!,single_char_str,&DAT_001 06011);
  std::string::operator=((string *)maybeTheFlag[abi:cxx11],local _48_password!);
  std::string::~string(local_48_password!);
  std::string::~string(single_char_str);
  std::string::~string(local_88);
                    /* try { // try from 00103868 to 0010387e has its C atchHandler @ 00103933 */
  this = std::operator<<((ostream *)std::cout,(string *)maybeT heFlag[abi:cxx11]);
  std::ostream::operator<<(this,std::endl<>);
  std::string::~string(final_FLAG);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Replicamos las operaciones en un script de python y obtenemos la flag:
``` python
import hashlib

def md5(data):
    return hashlib.md5(data).hexdigest()

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def maybe_get_flag(password: str = "Filitoni2") -> str:
    flag = bytearray()
    md5_password = md5(password.encode())

    for bc in range(len(md5_password)):
        current_char = md5_password[bc]
        md5_current_char = md5(current_char.encode())
        first_char = md5_current_char[0]
        new_byte = bc ^ ord(first_char) & 0x7b
        flag.append(new_byte)

    hashed = sha256(flag)

    final_flag = f"grodno{{{hashed}}}"
    return final_flag

result = maybe_get_flag()
print(result)
```

**Nota**: Ghidra falla al decompilar correctamente algunas funciones como `md5` o `sha256` asi que hay fijarse bien en el desensamblado y sobreescribir la firma de estas funciones.

` grodno{ea88897b06948c43c6c09ff49826e2b7ed2695b42f76223cb10484a4606b2114}`

