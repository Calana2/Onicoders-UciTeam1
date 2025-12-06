# Little Warm-up

```C

long main(int argc,char **argv)

{
  int iVar1;
  ostream *poVar2;
  long in_FS_OFFSET;
  allocator local_b9;
  allocator *local_b8;
  allocator *local_b0;
  string hardcoded_string [32];
  string password [32];
  string sha256_password [32];
  string md5_arg [40];
  long local_20;

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (argc < 2) {
    poVar2 = std::operator<<((ostream *)std::cout,"Usage: ./ma in.exe <password>");
    std::ostream::operator<<(poVar2,std::endl<>);
  }
  else {
    local_b8 = &local_b9;
                    /* try { // try from 0010268a to 0010268e has its C atchHandler @ 001027f9 */
    std::string::string<>
              (hardcoded_string,"63f907ed0c04f2fe1936c0caca8caf d1105216d91aab062dc8b99539d17e8849",
               &local_b9);
    std::__new_allocator<char>::~__new_allocator((__new_alloca tor<char> *)&local_b9);
    local_b0 = &local_b9;
                    /* try { // try from 001026ce to 001026d2 has its C atchHandler @ 0010282b */
    std::string::string<>(password,argv[1],&local_b9);
    std::__new_allocator<char>::~__new_allocator((__new_alloca tor<char> *)&local_b9);
                    /* try { // try from 001026f1 to 001026f5 has its Ca tchHandler @ 00102862 */
    sha256(sha256_password,password);
                    /* try { // try from 00102707 to 00102743 has its C atchHandler @ 00102851 */
    iVar1 = std::string::compare(hardcoded_string,sha256_pass word);
    if (iVar1 == 0) {
      poVar2 = std::operator<<((ostream *)std::cout,"You are rig ht! Your flag: grodno{");
      md5(md5_arg);
                    /* try { // try from 0010274e to 00102779 has its C atchHandler @ 00102840 */
      poVar2 = std::operator<<(poVar2,md5_arg);
      poVar2 = std::operator<<(poVar2,"}");
      std::ostream::operator<<(poVar2,std::endl<>);
      std::string::~string(md5_arg);
    }
    else {
                    /* try { // try from 0010279c to 001027b2 has its C atchHandler @ 00102851 */
      poVar2 = std::operator<<((ostream *)std::cout,"You are wr ong");
      std::ostream::operator<<(poVar2,std::endl<>);
    }
    std::string::~string(sha256_password);
    std::string::~string(password);
    std::string::~string(hardcoded_string);
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

El programa espera que se introduzca una contraseña cuyo hash sha-256 sea "63f907ed0c04f2fe1936c0caca8cafd1105216d91aab062dc8b99539d17e8849".

![2025-07-01-124609_1153x401_scrot](https://github.com/user-attachments/assets/d82bdaed-fe40-4e23-a37f-4f49b2174635)

La flag es el hash MD5 de la contraseña.

`grodno{cea48deb49d8e4dcaee47d1ee710c9ac}`
