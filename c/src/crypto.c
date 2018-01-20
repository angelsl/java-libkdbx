#include "kdbxouter.h"

#include <stdint.h>
#include <stddef.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <argon2.h>
#include <tomcrypt.h>

static int sha256_id = -1;
static int aes_id = -1;

#define CHECK_OK(expr, err) FAIL_IF((expr) != CRYPT_OK, err)

kdbxo_result kdbxo_crypto_init(void) {
    FAIL_IF(register_all_ciphers() == -1, "failed to register LTC ciphers");
    FAIL_IF(register_all_hashes() == -1, "failed to register LTC hashes");

    sha256_id = find_hash("sha256");
    FAIL_IF(sha256_id == -1, "could not find SHA256 hash");
    aes_id = find_cipher("aes");
    FAIL_IF(aes_id == -1, "could not find AES cipher");

    return RESULT_OK;
}

kdbxo_result kdbxo_sha256(void *dest32, const void *src, size_t srcsz) {
    hash_state md = { 0 };
    CHECK_OK(sha256_init(&md), "SHA256 init failed");
    CHECK_OK(sha256_process(&md, src, srcsz), "SHA256 process failed");
    CHECK_OK(sha256_done(&md, dest32), "SHA256 termination failed");
    return RESULT_OK;
}

kdbxo_result kdbxo_sha512(void *dest64, const void *src, size_t srcsz) {
    hash_state md = { 0 };
    CHECK_OK(sha512_init(&md), "SHA512 init failed");
    CHECK_OK(sha512_process(&md, src, srcsz), "SHA512 process failed");
    CHECK_OK(sha512_done(&md, dest64), "SHA512 termination failed");
    return RESULT_OK;
}

kdbxo_result kdbxo_hmacsha256(const void *key64, void *dest32, const void *src, size_t srcsz) {
    hmac_state st = { 0 };
    CHECK_OK(hmac_init(&st, sha256_id, key64, 64), "HMAC init failed");
    CHECK_OK(hmac_process(&st, src, srcsz), "HMAC process failed");
    unsigned long outlen = 32;
    CHECK_OK(hmac_done(&st, dest32, &outlen), "HMAC termination failed");
    return RESULT_OK;
}

kdbxo_result kdbxo_aes256cbc_d(const void *key32, const void *iv16, void *dest, const void *src, size_t srcsz) {
    symmetric_CBC st = { 0 };
    CHECK_OK(cbc_start(aes_id, iv16, key32, 32, 0, &st), "AES256CBC init failed");
    CHECK_OK(cbc_decrypt(src, dest, srcsz, &st), "AES256CBC decrypt failed");
    CHECK_OK(cbc_done(&st), "AES256CBC termination failed");
    return RESULT_OK;
}

kdbxo_result kdbxo_chacha20_d(const void *key32, const void *iv12, void *dest, const void *src, size_t srcsz) {
    chacha_state st = { 0 };
    CHECK_OK(chacha_setup(&st, key32, 32, 0), "ChaCha20 init failed");
    CHECK_OK(chacha_ivctr32(&st, iv12, 12, 0), "ChaCha20 set IV failed");
    CHECK_OK(chacha_crypt(&st, src, srcsz, dest), "ChaCha20 decrypt failed");
    CHECK_OK(chacha_done(&st), "ChaCha20 termination failed");
    return RESULT_OK;
}

typedef struct {
    const void *seed32;
    void *half;
    uint64_t rounds;
    kdbxo_result result;
} aeskdf_struct;

static kdbxo_result aeskdf_half(const void *seed32, void *key, uint64_t rounds) {
    symmetric_key st = { 0 };
    CHECK_OK(rijndael_setup(seed32, 32, 0, &st), "AESKDF setup failed");
    for (uint64_t i = 0; i < rounds; ++i) {
        CHECK_OK(rijndael_ecb_encrypt(key, key, &st), "AESKDF round failed");
    }
    rijndael_done(&st);
    return RESULT_OK;
}

static void *aeskdf_thread(void *data) {
    aeskdf_struct *p = data;
    aeskdf_half(p->seed32, p->half, p->rounds);
    return NULL;
}


kdbxo_result kdbxo_aeskdf(const void *seed32, void *key32, uint64_t rounds) {
    pthread_t t = 0;
    aeskdf_struct tp = {
        .seed32 = seed32,
        .half = (unsigned char *) key32 + 16,
        .rounds = rounds,
        .result = RESULT_ERR
    };
    if (pthread_create(&t, NULL, aeskdf_thread, &tp)) {
        kdbxo_set_error("AESKDF pthread create failed");
        return RESULT_ERR;
    }
    if (aeskdf_half(seed32, key32, rounds)) {
        return RESULT_ERR;
    }
    if (pthread_join(t, NULL)) {
        kdbxo_set_error("AESKDF pthread join failed");
        return RESULT_ERR;
    }
    if (kdbxo_sha256(key32, key32, 32)) {
        return RESULT_ERR;
    }
    return RESULT_OK;
}

kdbxo_result kdbxo_argon2kdf(uint32_t iter, uint32_t mem, uint32_t lanes, uint32_t version,
    void *key32,
    const void *salt, uint32_t saltlen,
    const void *secret, uint32_t secretlen,
    const void *ad, uint32_t adlen) {
    unsigned char out[32];
    argon2_context a2ctx = {
        .t_cost = iter,
        .m_cost = mem,
        .lanes = lanes,
        .threads = get_nprocs(),
        .version = version,
        .out = out,
        .outlen = 32,
        .pwd = key32,
        .salt = (void *) salt,
        .saltlen = saltlen,
        .pwdlen = 32,
        .secret = (void *) secret,
        .secretlen = secretlen,
        .ad = (void *) ad,
        .adlen = adlen,
        .flags = 0
    };
    int result = argon2d_ctx(&a2ctx);
    if (result != ARGON2_OK) {
        kdbxo_set_error(argon2_error_message(result));
        return RESULT_ERR;
    }

    memcpy(key32, out, 32);
    memset(out, 0, 32);
    return RESULT_OK;
}

typedef struct __attribute__((packed)) {
    uint32_t index;
    unsigned char hash[32];
    int32_t length;
    unsigned char data[];
} hashedblock_header;
_Static_assert(sizeof(hashedblock_header) == 40, "Hashed block stream header size should be 40");

size_t kdbxo_hashedblock_d(const void *const src, size_t srcsz, void **outp) {
    /*
        hashedBlock
        [uint index]
        [byte[32] hash = sha256(data)]
        [int len]
        [byte[len] data]
        hashedBlockStream
        [hashedBlock... blocks]
        [hashedBlock {hash = 0, len = 0} lastblock]
    */
    const unsigned char *cur = src;
    const unsigned char *const end = cur + srcsz;
    size_t outsz = 0;
    unsigned char *out = malloc(srcsz);
    if (!out) {
        kdbxo_set_error("malloc failed while decoding hashed block stream");
        return 0;
    }

    unsigned char *hash_buf[32];
    size_t count = 0;
    while (1) {
        if (cur + sizeof(hashedblock_header) > end) {
            kdbxo_set_error("unexpected EOF while decoding hashed block stream");
            goto fail;
        }
        const hashedblock_header *block_header = (const hashedblock_header*) cur;
        if (count != block_header->index) {
            kdbxo_set_error("wrong block index while decoding hashed block stream");
            goto fail;
        }
        if (block_header->length == 0) {
            int all_zero = 1;
            for (int i = 0; i < 32; ++i) {
                if (block_header->hash[i]) {
                    all_zero = 0;
                    break;
                }
            }
            if (all_zero) {
                break;
            }
        }
        if (block_header->data + block_header->length > end ||
            outsz + block_header->length > srcsz) {
            kdbxo_set_error("unexpected EOF while decoding hashed block stream");
            goto fail;
        }

        if (kdbxo_sha256(hash_buf, block_header->data, block_header->length)) {
            goto fail;
        }
        if (memcmp(hash_buf, block_header->hash, 32)) {
            kdbxo_set_error("hash mismatch while decoding hashed block stream; corrupted file?");
            goto fail;
        }

        memcpy(out + outsz, block_header->data, block_header->length);
        outsz += block_header->length;
        cur += sizeof(hashedblock_header) + block_header->length;
        ++count;
    }

    *outp = out;
    return outsz;
fail:
    free(out);
    *outp = NULL;
    return 0;
}

size_t kdbxo_hmacblock_d(const void *src, size_t srcsz, void **outp) {
    (void) src; (void) srcsz; (void) outp;
    // TODO
    return 0;
}

kdbxo_result kdbxo_hmac_block_key(void *dest64, const void *key, size_t keysz, uint64_t nonce) {
    unsigned char *noncep = (unsigned char *) &nonce;
    hash_state md;
    CHECK_OK(sha512_init(&md), "HMAC block key SHA512 init failed");
    CHECK_OK(sha512_process(&md, noncep, 8), "HMAC block key SHA512 process (1) failed");
    CHECK_OK(sha512_process(&md, key, keysz), "HMAC block key SHA512 process (2) failed");
    CHECK_OK(sha512_done(&md, dest64), "HMAC block key SHA512 termination failed");
    return RESULT_OK;
}

kdbxo_result kdbxo_crypto_key(const void *seed32, const void *key32, void *dest32) {
    hash_state md;
    CHECK_OK(sha256_init(&md), "Crypto key SHA256 init failed");
    CHECK_OK(sha256_process(&md, seed32, 32), "Crypto key SHA256 process (1) failed");
    CHECK_OK(sha256_process(&md, key32, 32), "Crypto key SHA256 process (2) failed");
    CHECK_OK(sha256_done(&md, dest32), "Crypto key SHA256 termination failed");
    return RESULT_OK;
}

kdbxo_result kdbxo_hmac_key(const void *seed32, const void *key32, void *dest64) {
    hash_state md;
    CHECK_OK(sha512_init(&md), "HMAC key SHA512 init failed");
    CHECK_OK(sha512_process(&md, seed32, 32), "HMAC key SHA512 process (1) failed");
    CHECK_OK(sha512_process(&md, key32, 32), "HMAC key SHA512 process (2) failed");
    uint8_t one = 1;
    CHECK_OK(sha512_process(&md, &one, 1), "HMAC key SHA512 process (3) failed");
    CHECK_OK(sha512_done(&md, dest64), "HMAC key SHA512 termination failed");
    return RESULT_OK;
}
