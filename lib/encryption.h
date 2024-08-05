#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <iostream>
#include <stdexcept>
#include <optional>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

namespace encryption
{

    const int SIZE_8_192            = 8192;
    const int KEY_SIZE_32           = 32;
    const int IV_SIZE_16            = 16;
    const int SHA_256_SIZE          = 32;
    const int AES_256_CBC_PADDING   = 16;

    struct encryption_data {

        unsigned char key[KEY_SIZE_32];
        unsigned char iv[IV_SIZE_16];

        encryption_data(const unsigned char *key);
        encryption_data(const unsigned char *key, const unsigned char *iv);
    };

    struct ip_addresses {

        char source_ip[64];
        char destination_ip[64];

        ip_addresses(unsigned char *buffer);
    };

    struct packet {

        unsigned char buffer[SIZE_8_192];
        size_t size;
        size_t max_capacity;

        packet();
        packet(unsigned char *data, size_t num);

        std::optional<packet> encrypt(encryption_data enc_data);
        std::optional<packet> decrypt(encryption_data enc_data);

        ip_addresses get_ip_addresses();

        bool getShaSum(unsigned char *output);
        bool valid_hash(unsigned char *hash);

        bool append(const unsigned char *data, size_t num);
        bool append(unsigned char data);
    };

    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);
}

#endif