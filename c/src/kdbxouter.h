#include <stddef.h>
#include <stdint.h>

#ifndef KDBXOUTER_H
#define KDBXOUTER_H
#define KDBX_SIG 0xB54BFB679AA2D903llu
#define FAIL_IF(cond, err) do { if (cond) { kdbxo_set_error(err); return RESULT_ERR; } } while ((void)0, 0)

typedef enum {
    RESULT_OK = 0,
    RESULT_END = 1,
    RESULT_ERR = -1
} kdbxo_result;

// crypto.c
extern kdbxo_result kdbxo_crypto_init(void);
extern kdbxo_result kdbxo_sha256(void *dest32, const void *src, size_t srcsz);
extern kdbxo_result kdbxo_sha512(void *dest64, const void *src, size_t srcsz);
extern kdbxo_result kdbxo_hmacsha256(const void *key64, void *dest32, const void *src, size_t srcsz);
extern kdbxo_result kdbxo_aes256cbc_d(const void *key32, const void *iv16, void *dest, const void *src, size_t srcsz);
extern kdbxo_result kdbxo_chacha20_d(const void *key32, const void *iv12, void *dest, const void *src, size_t srcsz);
extern kdbxo_result kdbxo_aeskdf(const void *seed32, void *key32, size_t rounds);
extern kdbxo_result kdbxo_argon2kdf(uint32_t iter, uint32_t mem, uint32_t lanes, uint32_t version,
    void *key32,
    const void *salt, uint32_t saltlen,
    const void *secret, uint32_t secretlen,
    const void *ad, uint32_t adlen);
extern size_t kdbxo_hashedblock_d(const void *const src, size_t srcsz, void **outp);
extern size_t kdbxo_hmacblock_d(const void *src, size_t srcsz, void **outp);
extern kdbxo_result kdbxo_hmac_block_key(void *dest64, const void *key, size_t keysz, uint64_t nonce);
extern kdbxo_result kdbxo_crypto_key(const void *seed32, const void *key32, void *dest32);
extern kdbxo_result kdbxo_hmac_key(const void *seed32, const void *key32, void *dest64);

// format.c
extern size_t kdbxo_unwrap(const char *in, size_t insz, const char *key32, void **outp);
extern const char *kdbxo_error;

static inline void kdbxo_set_error(const char *str) {
    if (kdbxo_error == NULL) {
        kdbxo_error = str;
    }
}
#endif // KDBXOUTER_H
