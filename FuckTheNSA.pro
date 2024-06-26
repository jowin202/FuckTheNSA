QT       += core gui serialport

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# run this optimizations on linux
#linux-g++{
QMAKE_CXXFLAGS += -mssse3 -msse4.1 -msse4.2 -mpclmul -msse2 -mavx2 -maes -msha
#}
QMAKE_CXXFLAGS += -DNDEBUG -g2 -O3 -fPIC -pthread -pipe


# fallback for windows because ...
#win32{
#QMAKE_CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
#QMAKE_CXXFLAGS += /arch:SSE2 /arch:SSE3 /arch:SSE4.1 /arch:SSE4.2 /arch:AVX /arch:AVX2 /arch:AES /arch:PCLMUL
#}


CONFIG(debug, debug|release) {
    DESTDIR = build/debug
} else {
    DESTDIR = build/release
}
# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    cipher.cpp \
    createtar.cpp \
    cryptopp/3way.cpp \
    cryptopp/adler32.cpp \
    cryptopp/algebra.cpp \
    cryptopp/algparam.cpp \
    cryptopp/allocate.cpp \
    cryptopp/arc4.cpp \
    cryptopp/aria.cpp \
    cryptopp/ariatab.cpp \
    cryptopp/asn.cpp \
    cryptopp/authenc.cpp \
    cryptopp/base32.cpp \
    cryptopp/base64.cpp \
    cryptopp/basecode.cpp \
    cryptopp/bfinit.cpp \
    cryptopp/blake2.cpp \
    cryptopp/blake2b_simd.cpp \
    cryptopp/blake2s_simd.cpp \
    cryptopp/blowfish.cpp \
    cryptopp/blumshub.cpp \
    cryptopp/camellia.cpp \
    cryptopp/cast.cpp \
    cryptopp/casts.cpp \
    cryptopp/cbcmac.cpp \
    cryptopp/ccm.cpp \
    cryptopp/chacha.cpp \
    cryptopp/chacha_avx.cpp \
    cryptopp/chacha_simd.cpp \
    cryptopp/chachapoly.cpp \
    cryptopp/cham.cpp \
    cryptopp/cham_simd.cpp \
    cryptopp/channels.cpp \
    cryptopp/cmac.cpp \
    cryptopp/cpu.cpp \
    cryptopp/crc.cpp \
    cryptopp/crc_simd.cpp \
    cryptopp/cryptlib.cpp \
    cryptopp/darn.cpp \
    cryptopp/default.cpp \
    cryptopp/des.cpp \
    cryptopp/dessp.cpp \
    cryptopp/dh.cpp \
    cryptopp/dh2.cpp \
    cryptopp/dll.cpp \
    cryptopp/dlltest.cpp \
    cryptopp/donna_32.cpp \
    cryptopp/donna_64.cpp \
    cryptopp/donna_sse.cpp \
    cryptopp/dsa.cpp \
    cryptopp/eax.cpp \
    cryptopp/ec2n.cpp \
    cryptopp/eccrypto.cpp \
    cryptopp/ecp.cpp \
    cryptopp/elgamal.cpp \
    cryptopp/emsa2.cpp \
    cryptopp/eprecomp.cpp \
    cryptopp/esign.cpp \
    cryptopp/files.cpp \
    cryptopp/filters.cpp \
    cryptopp/fips140.cpp \
    cryptopp/fipsalgt.cpp \
    cryptopp/fipstest.cpp \
    cryptopp/gcm.cpp \
    cryptopp/gcm_simd.cpp \
    cryptopp/gf256.cpp \
    cryptopp/gf2_32.cpp \
    cryptopp/gf2n.cpp \
    cryptopp/gf2n_simd.cpp \
    cryptopp/gfpcrypt.cpp \
    cryptopp/gost.cpp \
    cryptopp/gzip.cpp \
    cryptopp/hc128.cpp \
    cryptopp/hc256.cpp \
    cryptopp/hex.cpp \
    cryptopp/hight.cpp \
    cryptopp/hmac.cpp \
    cryptopp/hrtimer.cpp \
    cryptopp/ida.cpp \
    cryptopp/idea.cpp \
    cryptopp/integer.cpp \
    cryptopp/iterhash.cpp \
    cryptopp/kalyna.cpp \
    cryptopp/kalynatab.cpp \
    cryptopp/keccak.cpp \
    cryptopp/keccak_core.cpp \
    cryptopp/keccak_simd.cpp \
    cryptopp/lea.cpp \
    cryptopp/lea_simd.cpp \
    cryptopp/lsh256.cpp \
    cryptopp/lsh256_avx.cpp \
    cryptopp/lsh256_sse.cpp \
    cryptopp/lsh512.cpp \
    cryptopp/lsh512_avx.cpp \
    cryptopp/lsh512_sse.cpp \
    cryptopp/luc.cpp \
    cryptopp/mars.cpp \
    cryptopp/marss.cpp \
    cryptopp/md2.cpp \
    cryptopp/md4.cpp \
    cryptopp/md5.cpp \
    cryptopp/misc.cpp \
    cryptopp/modes.cpp \
    cryptopp/mqueue.cpp \
    cryptopp/mqv.cpp \
    cryptopp/nbtheory.cpp \
    cryptopp/neon_simd.cpp \
    cryptopp/oaep.cpp \
    cryptopp/osrng.cpp \
    cryptopp/padlkrng.cpp \
    cryptopp/panama.cpp \
    cryptopp/pch.cpp \
    cryptopp/pkcspad.cpp \
    cryptopp/poly1305.cpp \
    cryptopp/polynomi.cpp \
    cryptopp/power7_ppc.cpp \
    cryptopp/power8_ppc.cpp \
    cryptopp/power9_ppc.cpp \
    cryptopp/ppc_simd.cpp \
    cryptopp/primetab.cpp \
    cryptopp/pssr.cpp \
    cryptopp/pubkey.cpp \
    cryptopp/queue.cpp \
    cryptopp/rabbit.cpp \
    cryptopp/rabin.cpp \
    cryptopp/randpool.cpp \
    cryptopp/rc2.cpp \
    cryptopp/rc5.cpp \
    cryptopp/rc6.cpp \
    cryptopp/rdrand.cpp \
    cryptopp/rdtables.cpp \
    cryptopp/regtest1.cpp \
    cryptopp/regtest2.cpp \
    cryptopp/regtest3.cpp \
    cryptopp/regtest4.cpp \
    cryptopp/rijndael.cpp \
    cryptopp/rijndael_simd.cpp \
    cryptopp/ripemd.cpp \
    cryptopp/rng.cpp \
    cryptopp/rsa.cpp \
    cryptopp/rw.cpp \
    cryptopp/safer.cpp \
    cryptopp/salsa.cpp \
    cryptopp/scrypt.cpp \
    cryptopp/seal.cpp \
    cryptopp/seed.cpp \
    cryptopp/serpent.cpp \
    cryptopp/sha.cpp \
    cryptopp/sha3.cpp \
    cryptopp/sha_simd.cpp \
    cryptopp/shacal2.cpp \
    cryptopp/shacal2_simd.cpp \
    cryptopp/shake.cpp \
    cryptopp/shark.cpp \
    cryptopp/sharkbox.cpp \
    cryptopp/simeck.cpp \
    cryptopp/simon.cpp \
    cryptopp/simon128_simd.cpp \
    cryptopp/simple.cpp \
    cryptopp/skipjack.cpp \
    cryptopp/sm3.cpp \
    cryptopp/sm4.cpp \
    cryptopp/sm4_simd.cpp \
    cryptopp/sosemanuk.cpp \
    cryptopp/speck.cpp \
    cryptopp/speck128_simd.cpp \
    cryptopp/square.cpp \
    cryptopp/squaretb.cpp \
    cryptopp/sse_simd.cpp \
    cryptopp/strciphr.cpp \
    cryptopp/tea.cpp \
    cryptopp/tftables.cpp \
    cryptopp/threefish.cpp \
    cryptopp/tiger.cpp \
    cryptopp/tigertab.cpp \
    cryptopp/ttmac.cpp \
    cryptopp/tweetnacl.cpp \
    cryptopp/twofish.cpp \
    cryptopp/vmac.cpp \
    cryptopp/wake.cpp \
    cryptopp/whrlpool.cpp \
    cryptopp/xed25519.cpp \
    cryptopp/xtr.cpp \
    cryptopp/xtrcrypt.cpp \
    cryptopp/xts.cpp \
    cryptopp/zdeflate.cpp \
    cryptopp/zinflate.cpp \
    cryptopp/zlib.cpp \
    main.cpp \
    mainwindow.cpp \
    microtar/src/microtar.c \
    optionwindow.cpp \
    tpmkeygen.cpp

HEADERS += \
    cipher.h \
    createtar.h \
    cryptopp/3way.h \
    cryptopp/adhoc.cpp.proto \
    cryptopp/adler32.h \
    cryptopp/adv_simd.h \
    cryptopp/aes.h \
    cryptopp/aes_armv4.h \
    cryptopp/algebra.h \
    cryptopp/algparam.h \
    cryptopp/allocate.h \
    cryptopp/arc4.h \
    cryptopp/argnames.h \
    cryptopp/aria.h \
    cryptopp/arm_simd.h \
    cryptopp/asn.h \
    cryptopp/authenc.h \
    cryptopp/base32.h \
    cryptopp/base64.h \
    cryptopp/basecode.h \
    cryptopp/bench.h \
    cryptopp/blake2.h \
    cryptopp/blowfish.h \
    cryptopp/blumshub.h \
    cryptopp/camellia.h \
    cryptopp/cast.h \
    cryptopp/cbcmac.h \
    cryptopp/ccm.h \
    cryptopp/chacha.h \
    cryptopp/chachapoly.h \
    cryptopp/cham.h \
    cryptopp/channels.h \
    cryptopp/cmac.h \
    cryptopp/config.h \
    cryptopp/config_align.h \
    cryptopp/config_asm.h \
    cryptopp/config_cpu.h \
    cryptopp/config_cxx.h \
    cryptopp/config_dll.h \
    cryptopp/config_int.h \
    cryptopp/config_misc.h \
    cryptopp/config_ns.h \
    cryptopp/config_os.h \
    cryptopp/config_ver.h \
    cryptopp/cpu.h \
    cryptopp/crc.h \
    cryptopp/cryptlib.h \
    cryptopp/cryptopp.rc \
    cryptopp/darn.h \
    cryptopp/default.h \
    cryptopp/des.h \
    cryptopp/dh.h \
    cryptopp/dh2.h \
    cryptopp/dll.h \
    cryptopp/dmac.h \
    cryptopp/donna.h \
    cryptopp/donna_32.h \
    cryptopp/donna_64.h \
    cryptopp/donna_sse.h \
    cryptopp/drbg.h \
    cryptopp/dsa.h \
    cryptopp/eax.h \
    cryptopp/ec2n.h \
    cryptopp/eccrypto.h \
    cryptopp/ecp.h \
    cryptopp/ecpoint.h \
    cryptopp/elgamal.h \
    cryptopp/emsa2.h \
    cryptopp/eprecomp.h \
    cryptopp/esign.h \
    cryptopp/factory.h \
    cryptopp/fhmqv.h \
    cryptopp/files.h \
    cryptopp/filters.h \
    cryptopp/fips140.h \
    cryptopp/fltrimpl.h \
    cryptopp/gcm.h \
    cryptopp/gf256.h \
    cryptopp/gf2_32.h \
    cryptopp/gf2n.h \
    cryptopp/gfpcrypt.h \
    cryptopp/gost.h \
    cryptopp/gzip.h \
    cryptopp/hashfwd.h \
    cryptopp/hc128.h \
    cryptopp/hc256.h \
    cryptopp/hex.h \
    cryptopp/hight.h \
    cryptopp/hkdf.h \
    cryptopp/hmac.h \
    cryptopp/hmqv.h \
    cryptopp/hrtimer.h \
    cryptopp/ida.h \
    cryptopp/idea.h \
    cryptopp/integer.h \
    cryptopp/iterhash.h \
    cryptopp/kalyna.h \
    cryptopp/keccak.h \
    cryptopp/lea.h \
    cryptopp/lsh.h \
    cryptopp/lubyrack.h \
    cryptopp/luc.h \
    cryptopp/mars.h \
    cryptopp/md2.h \
    cryptopp/md4.h \
    cryptopp/md5.h \
    cryptopp/mdc.h \
    cryptopp/mersenne.h \
    cryptopp/misc.h \
    cryptopp/modarith.h \
    cryptopp/modes.h \
    cryptopp/modexppc.h \
    cryptopp/mqueue.h \
    cryptopp/mqv.h \
    cryptopp/naclite.h \
    cryptopp/nbtheory.h \
    cryptopp/nr.h \
    cryptopp/oaep.h \
    cryptopp/oids.h \
    cryptopp/osrng.h \
    cryptopp/ossig.h \
    cryptopp/padlkrng.h \
    cryptopp/panama.h \
    cryptopp/pch.h \
    cryptopp/pkcspad.h \
    cryptopp/poly1305.h \
    cryptopp/polynomi.h \
    cryptopp/ppc_simd.h \
    cryptopp/pssr.h \
    cryptopp/pubkey.h \
    cryptopp/pwdbased.h \
    cryptopp/queue.h \
    cryptopp/rabbit.h \
    cryptopp/rabin.h \
    cryptopp/randpool.h \
    cryptopp/rc2.h \
    cryptopp/rc5.h \
    cryptopp/rc6.h \
    cryptopp/rdrand.h \
    cryptopp/resource.h \
    cryptopp/rijndael.h \
    cryptopp/ripemd.h \
    cryptopp/rng.h \
    cryptopp/rsa.h \
    cryptopp/rw.h \
    cryptopp/safer.h \
    cryptopp/salsa.h \
    cryptopp/scrypt.h \
    cryptopp/seal.h \
    cryptopp/secblock.h \
    cryptopp/secblockfwd.h \
    cryptopp/seckey.h \
    cryptopp/seed.h \
    cryptopp/serpent.h \
    cryptopp/serpentp.h \
    cryptopp/sha.h \
    cryptopp/sha1_armv4.h \
    cryptopp/sha256_armv4.h \
    cryptopp/sha3.h \
    cryptopp/sha512_armv4.h \
    cryptopp/shacal2.h \
    cryptopp/shake.h \
    cryptopp/shark.h \
    cryptopp/simeck.h \
    cryptopp/simon.h \
    cryptopp/simple.h \
    cryptopp/siphash.h \
    cryptopp/skipjack.h \
    cryptopp/sm3.h \
    cryptopp/sm4.h \
    cryptopp/smartptr.h \
    cryptopp/sosemanuk.h \
    cryptopp/speck.h \
    cryptopp/square.h \
    cryptopp/stdcpp.h \
    cryptopp/strciphr.h \
    cryptopp/tea.h \
    cryptopp/threefish.h \
    cryptopp/tiger.h \
    cryptopp/trap.h \
    cryptopp/trunhash.h \
    cryptopp/ttmac.h \
    cryptopp/tweetnacl.h \
    cryptopp/twofish.h \
    cryptopp/vmac.h \
    cryptopp/wake.h \
    cryptopp/whrlpool.h \
    cryptopp/words.h \
    cryptopp/xed25519.h \
    cryptopp/xtr.h \
    cryptopp/xtrcrypt.h \
    cryptopp/xts.h \
    cryptopp/zdeflate.h \
    cryptopp/zinflate.h \
    cryptopp/zlib.h \
    mainwindow.h \
    microtar/src/microtar.h \
    optionwindow.h \
    tpmkeygen.h

FORMS += \
    mainwindow.ui \
    optionwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    cryptopp/Doxyfile \
    cryptopp/Filelist.txt \
    cryptopp/GNUmakefile \
    cryptopp/GNUmakefile-cross \
    cryptopp/History.txt \
    cryptopp/Install.txt \
    cryptopp/License.txt \
    cryptopp/Readme.txt \
    cryptopp/aes_armv4.S \
    cryptopp/bds10.zip \
    cryptopp/cryptdll.vcxproj \
    cryptopp/cryptdll.vcxproj.filters \
    cryptopp/cryptest.nmake \
    cryptopp/cryptest.sln \
    cryptopp/cryptest.vcxproj \
    cryptopp/cryptest.vcxproj.filters \
    cryptopp/cryptest.vcxproj.user \
    cryptopp/cryptlib.vcxproj \
    cryptopp/cryptlib.vcxproj.filters \
    cryptopp/cryptopp.supp \
    cryptopp/dlltest.vcxproj \
    cryptopp/dlltest.vcxproj.filters \
    cryptopp/rdrand.asm \
    cryptopp/rdseed.asm \
    cryptopp/sha1_armv4.S \
    cryptopp/sha256_armv4.S \
    cryptopp/sha512_armv4.S \
    cryptopp/vs2005.zip \
    cryptopp/x64dll.asm \
    cryptopp/x64masm.asm


