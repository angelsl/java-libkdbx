#include "kdbxouter.h"

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <argon2.h>
#include <tomcrypt.h>

static int sha256_id = -1;
static int aes_id = -1;

int kdbxo_crypto_init(void) {
    register_all_ciphers();
    register_all_hashes();

    sha256_id = find_hash("sha256");
    if (sha256_id == -1) {
        return 1;
    }
    aes_id = find_cipher("aes");
    if (aes_id == -1) {
        return 1;
    }

    return 0;
}

void kdbxo_sha256(void *dest32, const void *src, size_t srcsz) {
    hash_state md = { 0 };
    sha256_init(&md);
    sha256_process(&md, src, srcsz);
    sha256_done(&md, dest32);
}

void kdbxo_sha512(void *dest64, const void *src, size_t srcsz) {
    hash_state md = { 0 };
    sha512_init(&md);
    sha512_process(&md, src, srcsz);
    sha512_done(&md, dest64);
}

void kdbxo_hmacsha256(const void *key64, void *dest32, const void *src, size_t srcsz) {
    hmac_state st = { 0 };
    hmac_init(&st, sha256_id, key64, 64);
    hmac_process(&st, src, srcsz);
    unsigned long outlen = 32;
    hmac_done(&st, dest32, &outlen);
}

void kdbxo_aes256cbc_d(const void *key32, const void *iv16, void *dest, const void *src, size_t srcsz) {
    symmetric_CBC st = { 0 };
    cbc_start(aes_id, iv16, key32, 32, 0, &st);
    cbc_decrypt(src, dest, srcsz, &st);
    cbc_done(&st);
}

void kdbxo_chacha20_d(const void *key32, const void *iv12, void *dest, const void *src, size_t srcsz) {
    chacha_state st = { 0 };
    chacha_setup(&st, key32, 32, 0);
    chacha_ivctr32(&st, iv12, 12, 0);
    chacha_crypt(&st, src, srcsz, dest);
    chacha_done(&st);
}

typedef struct {
    const void *seed32;
    void *half;
    uint64_t rounds;
} aeskdf_struct;

static void aeskdf_half(const void *seed32, void *key, uint64_t rounds) {
    symmetric_key st = { 0 };
    rijndael_setup(seed32, 32, 0, &st);
    for (uint64_t i = 0; i < rounds; ++i) {
        rijndael_ecb_encrypt(key, key, &st);
    }
    rijndael_done(&st);
}

static void *aeskdf_thread(void *data) {
    aeskdf_struct *p = data;
    aeskdf_half(p->seed32, p->half, p->rounds);
    return NULL;
}


void kdbxo_aeskdf(const void *seed32, void *key32, uint64_t rounds) {
    pthread_t t = 0;
    aeskdf_struct tp = {
        .seed32 = seed32,
        .half = (unsigned char *) key32 + 16,
        .rounds = rounds
    };
    pthread_create(&t, NULL, aeskdf_thread, &tp);
    aeskdf_half(seed32, key32, rounds);
    pthread_join(t, NULL);
    kdbxo_sha256(key32, key32, 32);
}

void kdbxo_argon2kdf(void) {
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
        return 0;
    }

    unsigned char *hash_buf[32];
    size_t count = 0;
    while (1) {
        if (cur + sizeof(hashedblock_header) > end) {
            goto fail;
        }
        const hashedblock_header *block_header = (const hashedblock_header*) cur;
        if (count != block_header->index) {
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
            goto fail;
        }

        kdbxo_sha256(hash_buf, block_header->data, block_header->length);
        if (memcmp(hash_buf, block_header->hash, 32)) {
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

void kdbxo_hmac_block_key(void *dest64, const void *key, size_t keysz, uint64_t nonce) {
    unsigned char *noncep = (unsigned char *) &nonce;
    hash_state md;
    sha512_init(&md);
    sha512_process(&md, noncep, 8);
    sha512_process(&md, key, keysz);
    sha512_done(&md, dest64);
}

void kdbxo_crypto_key(const void *seed32, const void *key32, void *dest32) {
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, seed32, 32);
    sha256_process(&md, key32, 32);
    sha256_done(&md, dest32);
}

void kdbxo_hmac_key(const void *seed32, const void *key32, void *dest64) {
    hash_state md;
    sha512_init(&md);
    sha512_process(&md, seed32, 32);
    sha512_process(&md, key32, 32);
    uint8_t one = 1;
    sha512_process(&md, &one, 1);
    sha512_done(&md, dest64);
}
