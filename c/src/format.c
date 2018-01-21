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

enum inner_header_field_type {
    IHD_END = 0,
    IHD_IRS_ID = 1,
    IHD_IRS_KEY = 2,
    IHD_BINARY = 3
};

enum compression_type {
    COMPRESSION_NONE = 0,
    COMPRESSION_GZIP = 1
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
            const void *salt;
            size_t salt_sz;

            uint32_t parallelism;
            uint64_t memory;
            uint64_t iterations;
            uint32_t version;

            const void *secret;
            size_t secret_sz;
            const void *ad;
            size_t ad_sz;
        } argon2;
    } kdf_params;

    const void *seed;
    size_t seed_sz;

    kdbxo_irs_type irs;
    const void *irs_key;
    size_t irs_key_sz;

    const void *ssb;
    size_t ssb_sz;
} kdbx_header;

static kdbxo_result read_map(const char *data, size_t datasz, void *d,
    void (*handler)(void *d, enum map_type type, const char *name, size_t namesz, const void *val, size_t valsz)) {
    const char *const end = data + datasz;
    if (data + 2 > end) {
        kdbxo_set_error("unexpected EOF while reading KDBX map");
        return RESULT_ERR;
    }
    data++;
    if (*(const uint8_t *) (data++) > 1) {
        kdbxo_set_error("KDBX map structure too new");
        return RESULT_ERR;
    }

    while (1) {
        if (data + 1 > end) {
            kdbxo_set_error("unexpected EOF while reading KDBX map");
            return RESULT_ERR;
        }
        enum map_type type = (enum map_type) (*(const uint8_t *) data);
        if (type == MAP_NONE) {
            return RESULT_OK;
        }
        data += 1;

        if (data + 4 > end) {
            kdbxo_set_error("unexpected EOF while reading KDBX map");
            return RESULT_ERR;
        }
        size_t namesz = *(const uint32_t *) data;
        data += 4;

        const char *name = data;
        if (name + namesz + 4 > end) {
            kdbxo_set_error("unexpected EOF while reading KDBX map");
            return RESULT_ERR;
        }
        data += namesz;

        size_t valsz = *(const uint32_t *) data;
        data += 4;

        const char *val = data;
        if (val + valsz > end) {
            kdbxo_set_error("unexpected EOF while reading KDBX map");
            return RESULT_ERR;
        }
        data += valsz;

        if (handler) {
            handler(d, type, name, namesz, val, valsz);
        }
    }
}

static void kdfp_uuid(void *d, enum map_type type, const char *name, size_t namesz, const void *val, size_t valsz) {
    const void **uuidp = d;
    if (type != MAP_BYTEARRAY || valsz < 16 || namesz < 5 || memcmp("$UUID", name, 5)) {
        return;
    }
    *uuidp = val;
}

static void kdfp_aes(void *d, enum map_type type, const char *name, size_t namesz, const void *val, size_t valsz) {
    kdbx_header *hdr = d;
    if (namesz != 1) {
        return;
    }

    switch (*name) {
    case 'R':
        if (type != MAP_UINT64 || valsz < 8) { return; }
        hdr->kdf_params.aes.rounds = *(const uint64_t *) val;
        break;
    case 'S':
        if (type != MAP_BYTEARRAY) { return; }
        hdr->kdf_params.aes.seed = val;
        hdr->kdf_params.aes.seed_sz = valsz;
        break;
    }
}

static void kdfp_argon2(void *d, enum map_type type, const char *name, size_t namesz, const void *val, size_t valsz) {
    kdbx_header *hdr = d;
    if (namesz != 1) {
        return;
    }

    switch (*name) {
    case 'P':
        if (type != MAP_UINT32 || valsz < 4) { return; }
        hdr->kdf_params.argon2.parallelism = *(const uint32_t *) val;
        break;
    case 'M':
        if (type != MAP_UINT64 || valsz < 8) { return; }
        hdr->kdf_params.argon2.memory = *(const uint64_t *) val;
        break;
    case 'I':
        if (type != MAP_UINT64 || valsz < 8) { return; }
        hdr->kdf_params.argon2.iterations = *(const uint64_t *) val;
        break;
    case 'V':
        if (type != MAP_UINT32 || valsz < 4) { return; }
        hdr->kdf_params.argon2.version = *(const uint32_t *) val;
        break;
    case 'S':
        if (type != MAP_BYTEARRAY) { return; }
        hdr->kdf_params.argon2.salt = val;
        hdr->kdf_params.argon2.salt_sz = valsz;
        break;
    case 'K':
        if (type != MAP_BYTEARRAY) { return; }
        hdr->kdf_params.argon2.secret = val;
        hdr->kdf_params.argon2.secret_sz = valsz;
        break;
    case 'A':
        if (type != MAP_BYTEARRAY) { return; }
        hdr->kdf_params.argon2.ad = val;
        hdr->kdf_params.argon2.ad_sz = valsz;
        break;
    }
}

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
        hdr->irs = (kdbxo_irs_type) (*(const int32_t *) data);
        break;
    case HDR_KDF_PARAMETERS:
        (void)0;
        const void *uuid = NULL;
        read_map(data, datasz, &uuid, kdfp_uuid);
        if (!uuid) {
            break;
        }
        if (!memcmp(uuid, KDF_ARGON2_UUID, 16)) {
            hdr->kdf = KDF_ARGON2;
            read_map(data, datasz, hdr, kdfp_argon2);
        } else if (!memcmp(uuid, KDF_AES_UUID, 16)) {
            hdr->kdf = KDF_AES;
            read_map(data, datasz, hdr, kdfp_aes);
        } else {
            kdbxo_set_error("Invalid KDF");
            return RESULT_ERR;
        }
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
    FAIL_IF(!hdr->seed || !hdr->iv, "missing header fields");

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

    return RESULT_OK;
}

static kdbxo_result apply_kdf(kdbx_header *hdr, char *key32) {
    switch (hdr->kdf) {
    case KDF_AES:
        FAIL_IF(!hdr->kdf_params.aes.seed, "AESKDF seed missing");
        FAIL_IF(hdr->kdf_params.aes.seed_sz != 32, "AESKDF seed size wrong");
        return kdbxo_aeskdf(hdr->kdf_params.aes.seed, key32, hdr->kdf_params.aes.rounds);
    case KDF_ARGON2:
        return kdbxo_argon2kdf(
            (uint32_t) (hdr->kdf_params.argon2.iterations),
            (uint32_t) (hdr->kdf_params.argon2.memory / 1024),
            hdr->kdf_params.argon2.parallelism,
            hdr->kdf_params.argon2.version,
            key32,
            hdr->kdf_params.argon2.salt,
            hdr->kdf_params.argon2.salt_sz,
            hdr->kdf_params.argon2.secret,
            hdr->kdf_params.argon2.secret_sz,
            hdr->kdf_params.argon2.ad,
            hdr->kdf_params.argon2.ad_sz);
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

static uint8_t count_padding(kdbx_header *hdr, const void *data, size_t datasz) {
    switch (hdr->cipher) {
    case CIPHER_AES:
        return kdbxo_count_pkcs7(data, datasz);
    default:
        return 0;
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

static kdbxo_result kdbx3(const char *in, const char *const end, const char *key32, kdbxo_read_result **outp) {
    kdbx_header hdr = { 0 };
    const char *const file_start = in - sizeof(kdbx_magic);
    // TODO compute header checksum to pass to XML side for verification
    (void)file_start;
    while (1) {
        if (in + 3 > end) {
            return RESULT_ERR;
        }
        uint8_t type = *(const uint8_t *) in;
        size_t size = *(const uint16_t *) (in + 1);
        if (in + 3 + size > end) {
            return RESULT_ERR;
        }
        kdbxo_result r = process_hdr(&hdr, type, in + 3, size);
        in += 3 + size;
        if (r == RESULT_END) {
            break;
        } else if (r) {
            return RESULT_ERR;
        }
    }

    FAIL_IF(validate_hdr(&hdr), NULL);

    // kdbx3-specific header field
    FAIL_IF(!hdr.ssb, "stream start bytes missing");
    FAIL_IF(hdr.ssb_sz != 32, "stream start bytes size invalid");
    FAIL_IF(!hdr.irs_key, "IRS key missing");

    char crypto_key[32] = { 0 };
    {
        char transformed_key[32] = { 0 };
        memcpy(transformed_key, key32, 32);
        FAIL_IF(apply_kdf(&hdr, transformed_key) ||
                kdbxo_crypto_key(hdr.seed, transformed_key, crypto_key), NULL);
        ZERO_ARRAY(transformed_key);
    }

    const size_t padded_ptsz = end - in;
    char *const pt = malloc(padded_ptsz);
    FAIL_IF(!pt, "malloc failed in kdbx3");

    if (apply_cipher(&hdr, crypto_key, pt, in, padded_ptsz)) {
        ZERO_ARRAY(crypto_key);
        memset(pt, 0, padded_ptsz);
        free(pt);
        kdbxo_set_error("decryption failed; wrong key?");
        return RESULT_ERR;
    }
    ZERO_ARRAY(crypto_key);

    const size_t ptsz = padded_ptsz - count_padding(&hdr, pt, padded_ptsz);

    if (memcmp(pt, hdr.ssb, 32)) {
        memset(pt, 0, ptsz);
        free(pt);
        kdbxo_set_error("stream start bytes wrong; wrong key?");
        return RESULT_ERR;
    }

    void *unhashed = NULL;
    size_t unhashedsz = kdbxo_hashedblock_d(pt + 32, ptsz - 32, &unhashed);
    memset(pt, 0, ptsz);
    free(pt);
    FAIL_IF(!unhashedsz || !unhashed, "hashed block verification failed; wrong key?");

    char *xml;
    size_t xmlsz;
    if (hdr.compression == COMPRESSION_GZIP) {
        void *decomp = NULL;
        size_t decompsz = gunzip(unhashed, unhashedsz, &decomp);
        memset(unhashed, 0, unhashedsz);
        free(unhashed);
        FAIL_IF(!decomp || !decompsz, NULL);

        xml = decomp;
        xmlsz = decompsz;
    } else {
        xml = unhashed;
        xmlsz = unhashedsz;
    }

    kdbxo_read_result *rr = calloc(1, sizeof(kdbxo_read_result));
    rr->xml = xml;
    rr->xmlsz = xmlsz;
    rr->irs = hdr.irs;
    rr->irs_key = hdr.irs_key;
    rr->irs_key_sz = hdr.irs_key_sz;
    rr->to_free = xml;
    rr->binarysz = 0;
    memset(&hdr, 0, sizeof(hdr));
    *outp = rr;
    return RESULT_OK;
}

static kdbxo_result kdbx4_read_ihdr(kdbx_header *hdr, kdbxo_binary *bin, size_t *binsz, const char *ihdr, const char *const end, const char **ihdr_end) {
    if (binsz) {
        *binsz = 0;
    }
    size_t bin_idx = 0;
    while (1) {
        if (ihdr + 5 > end) {
            return RESULT_ERR;
        }
        enum inner_header_field_type type = (enum inner_header_field_type) *(const uint8_t *) ihdr;
        size_t size = *(const uint32_t *) (ihdr + 1);
        const char *data = ihdr + 5;
        if (data + size > end) {
            return RESULT_ERR;
        }
        if (hdr) {
            switch (type) {
            default:
            case IHD_END:
                break;
            case IHD_IRS_ID:
                FAIL_IF(size < 4, "not enough data in kdbx4_read_ihdr");
                hdr->irs = (kdbxo_irs_type) (*(const int32_t *) data);
                break;
            case IHD_IRS_KEY:
                hdr->irs_key = data;
                hdr->irs_key_sz = size;
                break;
            case IHD_BINARY:
                if (binsz) {
                    (*binsz)++;
                }
                break;
            }
        } else if (bin && type == IHD_BINARY) {
            FAIL_IF(size < 1, "not enough data in kdbx4_read_ihdr");
            kdbxo_binary *cur_bin = bin + (bin_idx++);
            cur_bin->data = data + 1;
            cur_bin->datasz = size - 1;
            cur_bin->prot = !!(*data & 1);
        }
        ihdr += 5 + size;
        if (type == IHD_END) {
            break;
        }
    }

    if (ihdr_end) {
        *ihdr_end = ihdr;
    }
    return RESULT_OK;
}

static size_t kdbx4(const char *in, const char *const end, const char *key32, kdbxo_read_result **outp) {
    kdbx_header hdr = { 0 };
    const char *const file_start = in - sizeof(kdbx_magic);
    while (1) {
        FAIL_IF(in + 5 > end, "unexpected EOF reading header");
        uint8_t type = *(const uint8_t *) in;
        size_t size = *(const uint32_t *) (in + 1);
        FAIL_IF(in + 5 + size > end, "unexpected EOF reading header");
        kdbxo_result r = process_hdr(&hdr, type, in + 5, size);
        in += 5 + size;
        if (r == RESULT_END) {
            break;
        }
        FAIL_IF(r, NULL);
    }

    FAIL_IF(in + 64 > end, "unexpected EOF");

    // check plaintext hash before we do anything else
    {
        char hdr_hash[32] = { 0 };
        FAIL_IF(kdbxo_sha256(hdr_hash, file_start, in - file_start), NULL);
        FAIL_IF(memcmp(hdr_hash, in, 32), "header checksum mismatch");
    }

    char crypto_key[32] = { 0 };
    char hmac_key[64] = { 0 };
    {
        char transformed_key[32] = { 0 };
        memcpy(transformed_key, key32, 32);
        int fail = apply_kdf(&hdr, transformed_key) ||
            kdbxo_crypto_key(hdr.seed, transformed_key, crypto_key) ||
            kdbxo_hmac_key(hdr.seed, transformed_key, hmac_key);
        ZERO_ARRAY(transformed_key);
        if (fail) {
            goto fail;
        }
    }

    {
        char hdr_hmac[32] = { 0 };
        char hdr_hmac_key[64] = { 0 };
        int fail = kdbxo_hmac_block_key(hdr_hmac_key, hmac_key, 64, 0xFFFFFFFFFFFFFFFFull) ||
            kdbxo_hmacsha256(hdr_hmac_key, hdr_hmac, file_start, in - file_start);
        ZERO_ARRAY(hdr_hmac_key);
        if (fail) {
            goto fail;
        }
        fail = memcmp(hdr_hmac, in + 32, 32);
        ZERO_ARRAY(hdr_hmac);
        if (fail) {
            kdbxo_set_error("header HMAC mismatch");
            goto fail;
        }

        in += 64;
    }

    if (validate_hdr(&hdr)) {
        goto fail;
    }

    size_t hmacsz = end - in;
    void *unhmac = NULL;
    const size_t padded_unhmacsz = kdbxo_hmacblock_d(in, hmacsz, hmac_key, &unhmac);
    in = NULL; // shouldn't be derefing in after this
    if (!padded_unhmacsz || !unhmac) {
        kdbxo_set_error("HMAC block verification failed; wrong key?");
        goto fail;
    }
    ZERO_ARRAY(hmac_key);

    char *pt = malloc(padded_unhmacsz);
    if (!pt) {
        free(unhmac);
        kdbxo_set_error("malloc failed in kdbx4");
        goto fail;
    }

    if (apply_cipher(&hdr, crypto_key, pt, unhmac, padded_unhmacsz)) {
        memset(pt, 0, padded_unhmacsz);
        free(pt);
        kdbxo_set_error("decryption failed; wrong key?");
        goto fail;
    }
    ZERO_ARRAY(crypto_key);
    free(unhmac); // no need to zero, this is still encrypted

    const size_t unhmacsz = padded_unhmacsz - count_padding(&hdr, pt, padded_unhmacsz);

    size_t ptsz;
    if (hdr.compression == COMPRESSION_GZIP) {
        void *decomp = NULL;
        size_t decompsz = gunzip(pt, unhmacsz, &decomp);
        memset(pt, 0, unhmacsz);
        free(pt);
        if (!decompsz || !decomp) {
            goto fail;
        }

        pt = decomp;
        ptsz = decompsz;
    } else {
        ptsz = unhmacsz;
    }

    const char *const ihdr = pt;
    const char *ihdr_end = NULL;
    size_t binsz;
    if (kdbx4_read_ihdr(&hdr, NULL, &binsz, ihdr, pt + ptsz, &ihdr_end)) {
        goto failpt;
    }
    kdbxo_read_result *rr = calloc(1, sizeof(kdbxo_read_result) + binsz*sizeof(kdbxo_binary));
    if (!rr) {
        goto failpt;
    }
    if (kdbx4_read_ihdr(NULL, rr->binary, NULL, ihdr, pt + ptsz, NULL)) {
        free(rr);
        goto failpt;
    }
    if (!hdr.irs_key) {
        kdbxo_set_error("IRS key missing");
        free(rr);
        goto failpt;
    }

    const char *const xml = ihdr_end;
    size_t xmlsz = ptsz - (xml - ihdr);
    rr->xml = xml;
    rr->xmlsz = xmlsz;
    rr->binarysz = binsz;
    rr->irs = hdr.irs;
    rr->irs_key = hdr.irs_key;
    rr->irs_key_sz = hdr.irs_key_sz;
    rr->to_free = pt;
    *outp = rr;
    memset(&hdr, 0, sizeof(hdr));

    return RESULT_OK;
failpt:
    memset(pt, 0, ptsz);
    free(pt);
fail:
    memset(&hdr, 0, sizeof(hdr));
    ZERO_ARRAY(crypto_key);
    ZERO_ARRAY(hmac_key);
    return RESULT_ERR;
}

kdbxo_result kdbxo_unwrap(const char *in, size_t insz, const char *key32, kdbxo_read_result **outp) {
    *outp = NULL;
    FAIL_IF(insz < sizeof(kdbx_magic), "file too short");
    const char *const end = in + insz;

    const kdbx_magic *hdr = (const kdbx_magic *) in;
    FAIL_IF(hdr->sig != KDBX_SIG, "invalid magic");
    FAIL_IF(hdr->ver_major < 2 || hdr->ver_major > 4, "unsupported version");

    in += sizeof(kdbx_magic);
    if (hdr->ver_major == 4) {
        return kdbx4(in, end, key32, outp);
    } else {
        return kdbx3(in, end, key32, outp);
    }
}

void kdbxo_free_read_result(kdbxo_read_result *rr) {
    if (!rr) { return; }
    // rr->xml is always in malloc'd memory (so RW), but the user doesn't
    // need to know that
    memset((char *) rr->xml, 0, rr->xmlsz);
    if (rr->to_free) { free(rr->to_free); }
    memset(rr, 0, sizeof(kdbxo_read_result) + rr->binarysz*sizeof(kdbxo_binary));
    free(rr);
}
