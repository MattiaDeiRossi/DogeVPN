#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "standards.h"
#include "data_structures.h"

namespace encryption
{

    void handleErrors(void);

    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);

    int encrypt(packet pkt, encryption_data enc_data, packet *enc_pkt);

    packet decrypt(packet encrypted_pkt, encryption_data enc_data);

    int getShaSum(const unsigned char *string, unsigned char *output);
}

#endif