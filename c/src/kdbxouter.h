#include <stddef.h>
#include <stdint.h>

#ifndef KDBXOUTER_H
#define KDBXOUTER_H
#define KDBX_SIG 0xB54BFB679AA2D903llu

// crypto.c
extern int kdbxo_crypto_init(void);
extern void kdbxo_sha256(void *dest32, const void *src, size_t srcsz);
extern void kdbxo_sha512(void *dest64, const void *src, size_t srcsz);
extern void kdbxo_hmacsha256(const void *key64, void *dest32, const void *src, size_t srcsz);
extern void kdbxo_aes256cbc_d(const void *key32, const void *iv16, void *dest, const void *src, size_t srcsz);
extern void kdbxo_chacha20_d(const void *key32, const void *iv12, void *dest, const void *src, size_t srcsz);
extern void kdbxo_aeskdf(const void *seed32, void *key32, size_t rounds);
extern void kdbxo_argon2kdf(void);
extern size_t kdbxo_hashedblock_d(const void *const src, size_t srcsz, void **outp);
extern size_t kdbxo_hmacblock_d(const void *src, size_t srcsz, void **outp);
extern void kdbxo_hmac_block_key(void *dest64, const void *key, size_t keysz, uint64_t nonce);
extern void kdbxo_crypto_key(const void *seed32, const void *key32, void *dest32);
extern void kdbxo_hmac_key(const void *seed32, const void *key32, void *dest64);

extern const char *kdbxo_error;
// format.c
extern size_t kdbxo_unwrap(const char *in, size_t insz, const char *key32, void **outp);
#endif // KDBXOUTER_H
