cmake_minimum_required(VERSION 3.0)
enable_language(C)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(ARGON2_SOURCES
    argon2/src/argon2.c
    argon2/src/core.c
    argon2/src/blake2/blake2b.c
    argon2/src/thread.c
    argon2/src/encoding.c
    argon2/src/opt.c)
add_library(argon2 STATIC ${ARGON2_SOURCES})
target_include_directories(argon2 PRIVATE argon2/src)
target_include_directories(argon2 PUBLIC argon2/include)
target_compile_definitions(argon2 PRIVATE "A2_VISCTL=1")
target_compile_options(argon2 PRIVATE "-std=c89;-O3;-Wall;-g;-pthread;-fPIC;-fvisibility=hidden")

set(TOMCRYPT_SOURCES
    tomcrypt/src/ciphers/aes/aes.c
    tomcrypt/src/hashes/helper/hash_file.c
    tomcrypt/src/hashes/helper/hash_filehandle.c
    tomcrypt/src/hashes/helper/hash_memory.c
    tomcrypt/src/hashes/helper/hash_memory_multi.c
    tomcrypt/src/hashes/sha2/sha224.c
    tomcrypt/src/hashes/sha2/sha256.c
    tomcrypt/src/hashes/sha2/sha384.c
    tomcrypt/src/hashes/sha2/sha512_224.c
    tomcrypt/src/hashes/sha2/sha512_256.c
    tomcrypt/src/hashes/sha2/sha512.c
    tomcrypt/src/mac/hmac/hmac_done.c
#    tomcrypt/src/mac/hmac/hmac_file.c
    tomcrypt/src/mac/hmac/hmac_init.c
    tomcrypt/src/mac/hmac/hmac_memory.c
    tomcrypt/src/mac/hmac/hmac_memory_multi.c
    tomcrypt/src/mac/hmac/hmac_process.c
    tomcrypt/src/mac/hmac/hmac_test.c
    tomcrypt/src/misc/adler32.c
    tomcrypt/src/misc/burn_stack.c
    tomcrypt/src/misc/compare_testvector.c
    tomcrypt/src/misc/copy_or_zeromem.c
    tomcrypt/src/misc/crc32.c
    tomcrypt/src/misc/crypt/crypt_argchk.c
    tomcrypt/src/misc/crypt/crypt.c
    tomcrypt/src/misc/crypt/crypt_cipher_descriptor.c
    tomcrypt/src/misc/crypt/crypt_cipher_is_valid.c
    tomcrypt/src/misc/crypt/crypt_constants.c
    tomcrypt/src/misc/crypt/crypt_find_cipher_any.c
    tomcrypt/src/misc/crypt/crypt_find_cipher.c
    tomcrypt/src/misc/crypt/crypt_find_cipher_id.c
    tomcrypt/src/misc/crypt/crypt_find_hash_any.c
    tomcrypt/src/misc/crypt/crypt_find_hash.c
    tomcrypt/src/misc/crypt/crypt_find_hash_id.c
    tomcrypt/src/misc/crypt/crypt_find_hash_oid.c
    tomcrypt/src/misc/crypt/crypt_find_prng.c
    tomcrypt/src/misc/crypt/crypt_fsa.c
    tomcrypt/src/misc/crypt/crypt_hash_descriptor.c
    tomcrypt/src/misc/crypt/crypt_hash_is_valid.c
    tomcrypt/src/misc/crypt/crypt_inits.c
    tomcrypt/src/misc/crypt/crypt_ltc_mp_descriptor.c
    tomcrypt/src/misc/crypt/crypt_prng_descriptor.c
    tomcrypt/src/misc/crypt/crypt_prng_is_valid.c
    tomcrypt/src/misc/crypt/crypt_prng_rng_descriptor.c
    tomcrypt/src/misc/crypt/crypt_register_all_ciphers.c
    tomcrypt/src/misc/crypt/crypt_register_all_hashes.c
    tomcrypt/src/misc/crypt/crypt_register_all_prngs.c
    tomcrypt/src/misc/crypt/crypt_register_cipher.c
    tomcrypt/src/misc/crypt/crypt_register_hash.c
    tomcrypt/src/misc/crypt/crypt_register_prng.c
    tomcrypt/src/misc/crypt/crypt_sizes.c
    tomcrypt/src/misc/crypt/crypt_unregister_cipher.c
    tomcrypt/src/misc/crypt/crypt_unregister_hash.c
    tomcrypt/src/misc/crypt/crypt_unregister_prng.c
    tomcrypt/src/misc/error_to_string.c
    tomcrypt/src/misc/mem_neq.c
    tomcrypt/src/misc/zeromem.c
    tomcrypt/src/modes/cbc/cbc_decrypt.c
    tomcrypt/src/modes/cbc/cbc_done.c
    tomcrypt/src/modes/cbc/cbc_encrypt.c
    tomcrypt/src/modes/cbc/cbc_getiv.c
    tomcrypt/src/modes/cbc/cbc_setiv.c
    tomcrypt/src/modes/cbc/cbc_start.c
    tomcrypt/src/modes/ecb/ecb_decrypt.c
    tomcrypt/src/modes/ecb/ecb_done.c
    tomcrypt/src/modes/ecb/ecb_encrypt.c
    tomcrypt/src/modes/ecb/ecb_start.c
    tomcrypt/src/stream/chacha/chacha_crypt.c
    tomcrypt/src/stream/chacha/chacha_done.c
    tomcrypt/src/stream/chacha/chacha_ivctr32.c
    tomcrypt/src/stream/chacha/chacha_ivctr64.c
    tomcrypt/src/stream/chacha/chacha_keystream.c
    tomcrypt/src/stream/chacha/chacha_setup.c
    tomcrypt/src/stream/chacha/chacha_test.c
    tomcrypt/src/stream/salsa20/salsa20_crypt.c
    tomcrypt/src/stream/salsa20/salsa20_done.c
    tomcrypt/src/stream/salsa20/salsa20_ivctr64.c
    tomcrypt/src/stream/salsa20/salsa20_keystream.c
    tomcrypt/src/stream/salsa20/salsa20_setup.c
    tomcrypt/src/stream/salsa20/salsa20_test.c)
add_library(tomcrypt STATIC ${TOMCRYPT_SOURCES})
target_include_directories(tomcrypt PUBLIC tomcrypt/src/headers)
target_compile_options(tomcrypt PRIVATE "-Wall;-Wsign-compare;-Wshadow;-Wextra"
                                PRIVATE "-Wsystem-headers;-Wbad-function-cast"
                                PRIVATE "-Wcast-align;-Wstrict-prototypes"
                                PRIVATE "-Wpointer-arith;-Wdeclaration-after-statement"
                                PRIVATE "-Wwrite-strings;-Wno-type-limits"
                                PRIVATE "-O3;-funroll-loops;-fomit-frame-pointer;-fPIC")
target_compile_definitions(tomcrypt PRIVATE "LTC_SOURCE"
                                    PUBLIC "LTC_NOTHING;LTC_NO_FILE"
                                    PUBLIC "LTC_RIJNDAEL;LTC_CHACHA;LTC_SALSA20"
                                    PUBLIC "LTC_ECB_MODE;LTC_CBC_MODE"
                                    PUBLIC "LTC_SHA256;LTC_SHA512"
                                    PUBLIC "LTC_HMAC;LTC_HASH_HELPERS")

set(KDBXOUTER_SOURCES
    src/crypto.c
    src/format.c)
add_library(kdbxouter SHARED ${KDBXOUTER_SOURCES})
target_link_libraries(kdbxouter argon2 tomcrypt pthread z)
target_compile_options(kdbxouter PRIVATE "-std=c11;-g;-Wall;-Wextra;-pedantic"
                                 PRIVATE "-pthread")
target_compile_options(kdbxouter PRIVATE "$<$<CONFIG:Debug>:-Og>")
target_compile_options(kdbxouter PRIVATE "$<$<CONFIG:Release>:-O3>")

if(KDBXOUTER_TEST)
    add_executable(testkdbxouter test.c)
    target_link_libraries(testkdbxouter kdbxouter)
    target_compile_options(testkdbxouter PRIVATE "-std=c11;-g;-Og;-Wall;-Wextra;-pedantic"
                                         PRIVATE "-pthread")
endif()
