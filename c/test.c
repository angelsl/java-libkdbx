#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/kdbxouter.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("usage: %s <file> <key>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    size_t fsz = ftell(f);
    fseek(f, 0, SEEK_SET);

    void *data = malloc(fsz);
    if (!data) {
        printf("malloc failed\n");
        fclose(f);
        return 1;
    }

    if (fread(data, 1, fsz, f) != fsz) {
        printf("fread failed\n");
        fclose(f);
        return 1;
    }

    fclose(f);

    char key[32];
    if (kdbxo_crypto_init()) {
        printf("kdbxo_init failed\n");
        return 1;
    }
    kdbxo_sha256(key, argv[2], strlen(argv[2]));
    kdbxo_sha256(key, key, 32);

    kdbxo_read_result *rr;
    kdbxo_result res = kdbxo_unwrap(data, fsz, key, &rr);
    if (res) {
        printf("failed: %s\n", kdbxo_error ? kdbxo_error : "no error");
        return 1;
    }

    fwrite(rr->xml, 1, rr->xmlsz, stdout);
    kdbxo_free_read_result(rr);
    free(data);
    return 0;
}
