#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace encryption
{

    const int MAX_UDP_MESSAGE_SIZE = 32768;
    const int MAX_KEY_SIZE = 32;
    const int MAX_IV_SIZE = 16;
    const int SHA_256_SIZE = 32;
    const int AES_256_CBC_PADDING = 16;

    struct packet {
        unsigned char message[MAX_UDP_MESSAGE_SIZE];
        long int length;
    };

    typedef struct packet packet;

    struct encryption_data {
        unsigned char key[MAX_KEY_SIZE];
        unsigned char iv[MAX_IV_SIZE];
    };

    typedef struct encryption_data encryption_data;

    void handleErrors(void);

    int encrypt(packet pkt, encryption_data enc_data, packet *enc_pkt);

    packet decrypt(packet encrypted_pkt, encryption_data enc_data);

    int getShaSum(packet message, unsigned char *output);

    int hash_verify(packet decrypted_message, unsigned char *hash, encryption_data enc_data);
}

#endif