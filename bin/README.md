In binary releases, this directory constains statically linked
binaries. They include code from the following projects, whose licenses
are thus provided in separate files:
- Boost
- glibc
- libsodium
- GMP
- OpenSSl
- NTL
- SimpleOT
- SimplestOT_C
- libOTe
- cryptoTools
- simde
- sse2neon

The binaries also include code from libstdc++ and libgcc. They have
been produced using `Scripts/build.sh` and standard GCC from
Devtoolset-6 on CentOS 6 and therefore satisfy the [GCC Runtime Library
Exception](https://www.gnu.org/licenses/gcc-exception-3.1.en.html).
