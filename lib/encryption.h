#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace encryption
{

    const int SIZE_32_768           =         32768;
    const int SIZE_4_096 =          4096;
    const int SIZE_8_192 =          8192;
    const int MAX_KEY_SIZE =        32;
    const int MAX_IV_SIZE =         16;
    const int SHA_256_SIZE =            32;
    const int AES_256_CBC_PADDING   = 16;

    struct packet {

        unsigned char buffer[SIZE_8_192];
        ssize_t size;
        size_t max_capacity;

        packet();
        packet(unsigned char *data, size_t num);
    };

    struct encryption_data {
        unsigned char key[MAX_KEY_SIZE];
        unsigned char iv[MAX_IV_SIZE];
    };

    void handleErrors(void);

    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);

    int encrypt(packet pkt, encryption_data enc_data, packet *enc_pkt);

    packet decrypt(packet encrypted_pkt, encryption_data enc_data);

    int getShaSum(packet message, unsigned char *output);

    int hash_verify(packet decrypted_message, unsigned char *hash);

    int append(packet *output, unsigned char *data, size_t num);

    int append(packet *output, unsigned char data);
}

#endif