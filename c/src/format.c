#include "kdbxouter.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

const char *kdbxo_error = NULL;

typedef struct __attribute__((packed)) {
    uint64_t sig;
    uint16_t ver_minor;
    uint16_t ver_major;
} kdbx_magic;
_Static_assert(sizeof(kdbx_magic) == 12, "KDBX header should be 12 bytes");

enum header_field_type {
    HDR_END = 0,
    HDR_COMMENT = 1,
    HDR_CIPHER_ID = 2,
    HDR_COMPRESSION_FLAGS = 3,
    HDR_MASTER_SEED = 4,
    HDR_TRANSFORM_SEED = 5,
    HDR_TRANSFORM_ROUNDS = 6,
    HDR_ENCRYPTION_IV = 7,
    HDR_IRS_KEY = 8,
    HDR_STREAM_START_BYTES = 9,
    HDR_IRS_ID = 10,
    HDR_KDF_PARAMETERS = 11,
    HDR_PUBLIC_CUSTOM_DATA = 12
};

enum compression_type {
    COMPRESSION_NONE = 0,
    COMPRESSION_GZIP = 1
};

enum irs_type {
    IRS_NULL = 0,
    IRS_ARCFOURVARIANT = 1,
    IRS_SALSA20 = 2,
    IRS_CHACHA20 = 3
};

enum map_type {
    MAP_NONE = 0,
    // MAP_BYTE = 0x02,
    // MAP_UINT16 = 0x03,
    MAP_UINT32 = 0x04,
    MAP_UINT64 = 0x05,
    MAP_BOOL = 0x08,
    // MAP_SBYTE = 0x0A,
    // MAP_INT16 = 0x0B,
    MAP_INT32 = 0x0C,
    MAP_INT64 = 0x0D,
    // MAP_FLOAT = 0x10,
    // MAP_DOUBLE = 0x11,
    // MAP_DECIMAL = 0x12,
    // MAP_CHAR = 0x17,
    MAP_STRING = 0x18,
    MAP_BYTEARRAY = 0x42
};

enum cipher_type {
    CIPHER_ERR = 0,
    CIPHER_AES = 1,
    CIPHER_CHACHA20 = 2
};

const uint8_t CIPHER_AES_UUID[] = { 0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff };
const uint8_t CIPHER_CHACHA20_UUID[] = { 0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A };

enum kdf_type {
    KDF_ERR = 0,
    KDF_AES = 1,
    KDF_ARGON2 = 2
};

const uint8_t KDF_AES_UUID[] = { 0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA };
const uint8_t KDF_ARGON2_UUID[] = { 0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C };

typedef struct {
    enum cipher_type cipher;

    const void *iv;
    size_t iv_sz;

    enum compression_type compression;

    enum kdf_type kdf;
    union {
        struct {
            const void *seed;
            size_t seed_sz;
            uint64_t rounds;
        } aes;
        struct {
            int todo;
        } argon2;
    } kdf_params;

    const void *seed;
    size_t seed_sz;

    enum irs_type irs;
    const void *irs_key;
    size_t irs_key_sz;

    const void *ssb;
    size_t ssb_sz;
} kdbx_header;

static kdbxo_result process_hdr(kdbx_header *hdr, uint8_t type, const char *data, size_t datasz) {
    switch (type) {
    case HDR_CIPHER_ID:
        FAIL_IF(datasz < 16, "not enough data in process_hdr");
        if (!memcmp(CIPHER_AES_UUID, data, 16)) {
            hdr->cipher = CIPHER_AES;
        } else if (!memcmp(CIPHER_CHACHA20_UUID, data, 16)) {
            hdr->cipher = CIPHER_CHACHA20;
        } else {
            kdbxo_set_error("Invalid cipher");
            return RESULT_ERR;
        }
        break;
    case HDR_COMPRESSION_FLAGS:
        FAIL_IF(datasz < 4, "not enough data in process_hdr");
        hdr->compression = (enum compression_type) (*(const int32_t *) data);
        break;
    case HDR_MASTER_SEED:
        FAIL_IF(datasz < 32, "not enough data in process_hdr");
        hdr->seed = data;
        hdr->seed_sz = datasz;
        break;
    case HDR_TRANSFORM_SEED:
        FAIL_IF(hdr->kdf != KDF_ERR && hdr->kdf != KDF_AES,
            "AES transform seed in header but KDF is not AES");
        hdr->kdf = KDF_AES;
        hdr->kdf_params.aes.seed = data;
        hdr->kdf_params.aes.seed_sz = datasz;
        break;
    case HDR_TRANSFORM_ROUNDS:
        FAIL_IF(datasz < 8, "not enough data in process_hdr");
        FAIL_IF(hdr->kdf != KDF_ERR && hdr->kdf != KDF_AES,
            "AES transform rounds in header but KDF is not AES");
        hdr->kdf = KDF_AES;
        hdr->kdf_params.aes.rounds = *(const uint64_t *) data;
        break;
    case HDR_ENCRYPTION_IV:
        hdr->iv = data;
        hdr->iv_sz = datasz;
        break;
    case HDR_IRS_KEY:
        hdr->irs_key = data;
        hdr->irs_key_sz = datasz;
        break;
    case HDR_STREAM_START_BYTES:
        FAIL_IF(datasz < 32, "not enough data in process_hdr");
        hdr->ssb = data;
        hdr->ssb_sz = datasz;
        break;
    case HDR_IRS_ID:
        FAIL_IF(datasz < 4, "not enough data in process_hdr");
        hdr->irs = (enum irs_type) (*(const int32_t *) data);
        break;
    case HDR_KDF_PARAMETERS:
        // TODO
        break;
    case HDR_PUBLIC_CUSTOM_DATA:
    case HDR_COMMENT:
    default:
        break;
    case HDR_END:
        return RESULT_END;
    }

    return RESULT_OK;
}

static kdbxo_result validate_hdr(kdbx_header *hdr) {
    FAIL_IF(!hdr->seed || !hdr->iv || !hdr->irs_key, "not enough data in process_hdr");

    switch (hdr->kdf) {
    case KDF_AES:
    case KDF_ARGON2:
        break;
    default:
        kdbxo_set_error("invalid KDF");
        return RESULT_ERR;
    }

    switch (hdr->cipher) {
    case CIPHER_AES:
    case CIPHER_CHACHA20:
        break;
    default:
        kdbxo_set_error("invalid cipher");
        return RESULT_ERR;
    }

    switch (hdr->compression) {
    case COMPRESSION_GZIP:
    case COMPRESSION_NONE:
        break;
    default:
        kdbxo_set_error("invalid compression");
        return RESULT_ERR;
    }

    switch (hdr->irs) {
    case IRS_CHACHA20:
    case IRS_SALSA20:
        break;
    case IRS_ARCFOURVARIANT: // not supported
    default:
        kdbxo_set_error("invalid IRS");
        return RESULT_ERR;
    }

    return RESULT_OK;
}

static kdbxo_result apply_kdf(kdbx_header *hdr, char *key32) {
    switch (hdr->kdf) {
    case KDF_AES:
        FAIL_IF(!hdr->kdf_params.aes.seed, "AESKDF seed missing");
        FAIL_IF(hdr->kdf_params.aes.seed_sz != 32, "AESKDF seed size wrong");
        return kdbxo_aeskdf(hdr->kdf_params.aes.seed, key32, hdr->kdf_params.aes.rounds);
    case KDF_ARGON2:
        return RESULT_ERR;
    default:
        kdbxo_set_error("invalid KDF");
        return RESULT_ERR;
    }
}

static kdbxo_result apply_cipher(kdbx_header *hdr, char *key32, char *out, const char *in, size_t sz) {
    switch (hdr->cipher) {
    case CIPHER_AES:
        FAIL_IF(hdr->iv_sz != 16, "invalid IV length for AES");
        return kdbxo_aes256cbc_d(key32, hdr->iv, out, in, sz);
    case CIPHER_CHACHA20:
        FAIL_IF(hdr->iv_sz != 12, "invalid IV length for ChaCha20");
        if (hdr->iv_sz != 12) {
            kdbxo_set_error("invalid IV length for ChaCha20");
            return RESULT_ERR;
        }
        return kdbxo_chacha20_d(key32, hdr->iv, out, in, sz);
    default:
        kdbxo_set_error("invalid cipher");
        return RESULT_ERR;
    }
}

static size_t gunzip(const void *src, size_t srcsz, void **outp) {
    size_t outsz = srcsz * 2;
    unsigned char *out = malloc(outsz);
    FAIL_IF(!out, "malloc failed in gunzip");

    z_stream s = { 0 };
    s.avail_in = srcsz;
    s.avail_out = outsz;
    s.next_in = (Bytef *) src;
    s.next_out = (Bytef *) out;

    s.zalloc = Z_NULL;
    s.zfree = Z_NULL;
    s.opaque = Z_NULL;

    int err = -1;
    size_t ret = 0;

    err = inflateInit2(&s, 15 + 32);
    if (err == Z_OK) {
        while (1) {
            err = inflate(&s, Z_FINISH);
            switch (err) {
            case Z_STREAM_END:
                ret = s.total_out;
                goto success;
            case Z_BUF_ERROR:
                outsz *= 2;
                void *out2 = realloc(out, outsz);
                FAIL_IF(!out2, "realloc failed in gunzip");
                out = out2;
                s.avail_out = outsz - s.total_out;
                s.next_out = (Bytef *) (out + s.total_out);
                break;
            case Z_STREAM_ERROR:
                kdbxo_set_error("zlib error (Z_STREAM_ERROR)");
                goto fail;
            case Z_DATA_ERROR:
                kdbxo_set_error("zlib error (Z_DATA_ERROR)");
                goto fail;
            case Z_MEM_ERROR:
                kdbxo_set_error("zlib error (Z_MEM_ERROR)");
                goto fail;
            case Z_VERSION_ERROR:
                kdbxo_set_error("zlib error (Z_VERSION_ERROR)");
                goto fail;
            default:
                kdbxo_set_error("unknown zlib error");
                goto fail;
            }
        }
    }

success:
    inflateEnd(&s);
    *outp = out;
    return ret;
fail:
    inflateEnd(&s);
    free(out);
    return 0;
}

static size_t kdbx3(const char *in, const char *const end, const char *key32, void **outp) {
    kdbx_header hdr = { 0 };
    while (1) {
        if (in + 3 > end) {
            return 0;
        }
        uint8_t type = *(const uint8_t *) in;
        size_t size = *(const uint16_t *) (in + 1);
        if (in + 3 + size > end) {
            return 0;
        }
        kdbxo_result r = process_hdr(&hdr, type, in + 3, size);
        in += 3 + size;
        if (r == RESULT_END) {
            break;
        } else if (r) {
            return 0;
        }
    }

    if (validate_hdr(&hdr)) {
        return 0;
    }

    // kdbx3-specific header field
    if (!hdr.ssb) {
        kdbxo_set_error("stream start bytes missing");
        return 0;
    }

    if (hdr.ssb_sz != 32) {
        kdbxo_set_error("stream start bytes size invalid");
        return 0;
    }

    char crypto_key[32] = { 0 };
    {
        char transformed_key[32] = { 0 };
        memcpy(transformed_key, key32, 32);
        if (apply_kdf(&hdr, transformed_key) ||
            kdbxo_crypto_key(hdr.seed, transformed_key, crypto_key)) {
            return 0;
        }
        memset(transformed_key, 0, 32);
    }

    const size_t ptsz = end - in;
    char *const pt = malloc(ptsz);
    if (!pt) {
        kdbxo_set_error("malloc failed in kdbx3");
        return 0;
    }

    if (apply_cipher(&hdr, crypto_key, pt, in, ptsz)) {
        memset(pt, 0, ptsz);
        free(pt);
        kdbxo_set_error("decryption failed; wrong key?");
        return 0;
    }

    if (memcmp(pt, hdr.ssb, 32)) {
        memset(pt, 0, ptsz);
        free(pt);
        kdbxo_set_error("stream start bytes wrong; wrong key?");
        return 0;
    }

    void *unhashed = NULL;
    size_t unhashedsz = kdbxo_hashedblock_d(pt + 32, ptsz - 32, &unhashed);
    memset(pt, 0, ptsz);
    free(pt);
    if (!unhashedsz || !unhashed) {
        kdbxo_set_error("hashed block verification failed; wrong key?");
        return 0;
    }

    if (hdr.compression == COMPRESSION_GZIP) {
        void *decomp = NULL;
        size_t decompsz = gunzip(unhashed, unhashedsz, &decomp);
        memset(unhashed, 0, unhashedsz);
        free(unhashed);
        if (!decompsz || !decomp) {
            return 0;
        }

        *outp = decomp;
        return decompsz;
    } else {
        *outp = unhashed;
        return unhashedsz;
    }
}

static size_t kdbx4(const char *in, const char *const end, const char *key32, void **outp) {
    // TODO
    (void) in; (void) end; (void) key32; (void) outp;
    return 0;
}

size_t kdbxo_unwrap(const char *in, size_t insz, const char *key32, void **outp) {
    if (insz < sizeof(kdbx_magic)) {
        kdbxo_set_error("file too short");
        return 0;
    }
    const char *const end = in + insz;

    const kdbx_magic *hdr = (const kdbx_magic *) in;
    if (hdr->sig != KDBX_SIG) {
        kdbxo_set_error("invalid magic");
        return 0;
    }

    if (hdr->ver_major < 2 || hdr->ver_major > 4) {
        kdbxo_set_error("unsupported version");
        return 0;
    }

    in += sizeof(kdbx_magic);
    if (hdr->ver_major == 4) {
        return kdbx4(in, end, key32, outp);
    } else {
        return kdbx3(in, end, key32, outp);
    }
}
