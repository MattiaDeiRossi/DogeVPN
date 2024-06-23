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

    int getShaSum(packet message, unsigned char *output);

    int hash_verify(packet decrypted_message, unsigned char *hash, encryption_data enc_data);

    int create_encrypted_packet(char *message, size_t length, encryption_data enc_data, packet *enc_pkt);
}

#endif