#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "src/kdbxouter.h"

static void printhex(const void *in, size_t sz) {
    const unsigned char *hex = in;
    static char hd[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    for (size_t i = 0; i < sz; ++i) {
        printf("%c%c", hd[(hex[i] & 0xFF) >> 4], hd[hex[i] & 0xF]);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <file> <key>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    size_t fsz = ftell(f);
    fseek(f, 0, SEEK_SET);

    void *data = malloc(fsz);
    if (!data) {
        fprintf(stderr, "malloc failed\n");
        fclose(f);
        return 1;
    }

    if (fread(data, 1, fsz, f) != fsz) {
        fprintf(stderr, "fread failed\n");
        fclose(f);
        return 1;
    }

    fclose(f);

    char key[32];
    if (kdbxo_crypto_init()) {
        fprintf(stderr, "kdbxo_init failed\n");
        return 1;
    }
    kdbxo_sha256(key, argv[2], strlen(argv[2]));
    kdbxo_sha256(key, key, 32);

    kdbxo_read_result *rr;
    kdbxo_result res = kdbxo_unwrap(data, fsz, key, &rr);
    if (res) {
        fprintf(stderr, "failed: %s\n", kdbxo_error ? kdbxo_error : "no error");
        return 1;
    }

    if (rr->irs_key) {
        printf("IRS type: %d\nIRS key: ", rr->irs);
        printhex(rr->irs_key, rr->irs_key_sz);
        printf("\n");
    }
    printf("Binary count: %zd\n", rr->binarysz);
    for (size_t i = 0; i < rr->binarysz; ++i) {
        kdbxo_binary *bin = rr->binary + i;
        printf("Binary %zd (protected: %d): ", i, bin->prot);
        printhex(bin->data, bin->datasz);
        printf("\n");
    }
    fwrite(rr->xml, 1, rr->xmlsz, stdout);
    kdbxo_free_read_result(rr);
    free(data);
    return 0;
}
