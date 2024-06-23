#include "encryption.h"

namespace encryption
{

    void handleErrors(void)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext)
    {
        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
            ERR_print_errors_fp(stderr);

        /* Initialise the encryption operation. */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            ERR_print_errors_fp(stderr);

        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            ERR_print_errors_fp(stderr);
        ciphertext_len = len;

        /* Finalise the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
            ERR_print_errors_fp(stderr);
        ciphertext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
    }

    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext)
    {
        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
            ERR_print_errors_fp(stderr);

        /* Initialise the decryption operation. */
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            ERR_print_errors_fp(stderr);

        /* Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            ERR_print_errors_fp(stderr);
        plaintext_len = len;

        /* Finalise the decryption. Further plaintext bytes may be written at
         * this stage.
         */
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
            ERR_print_errors_fp(stderr);
        plaintext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return plaintext_len;
    }

    int encrypt(packet pkt, encryption_data enc_data, packet *enc_pkt)
    {
        
        int ret_val = 0;

        /* Checking the length for returning an error in case of an UDP packet too large.
        *  Abusing plus one just for lazyness and safetyness, ignoring modules.
        */
        size_t ciphertext_len = ((pkt.length / KEY_LEN) + 1) * KEY_LEN;
        if (ciphertext_len > UDP_THEORETICAL_LIMIT) {
            ret_val = UDP_PACKET_TOO_LARGE;
            return ret_val;
        }

        packet encrypted_pkt;
        encrypted_pkt.length = encryption::encrypt(
            pkt.message, pkt.length, 
            enc_data.key, enc_data.iv, 
            encrypted_pkt.message
        );

        *enc_pkt = encrypted_pkt;
        return ret_val;
    }

    packet decrypt(packet encrypted_pkt, encryption_data enc_data)
    {

        packet pkt;
        pkt.length = encryption::decrypt(
            encrypted_pkt.message, encrypted_pkt.length, 
            enc_data.key, enc_data.iv, 
            pkt.message
        );

        return pkt;
    }

    // Change output with typedef.
    int getShaSum(packet pkt, unsigned char *output)
    {

        EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
        unsigned char mdVal[SHA_256_BYTES];
        unsigned int mdLen, i;

        if (!EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL))
        {
            // printf("Message digest initialization failed.\n");
            EVP_MD_CTX_free(mdCtx);
            return -1;
        }

        // Hashes cnt bytes of data at d into the digest context mdCtx
        if (!EVP_DigestUpdate(mdCtx, pkt.message, pkt.length))
        {
            // printf("Message digest update failed.\n");
            EVP_MD_CTX_free(mdCtx);
            return -1;
        }

        if (!EVP_DigestFinal_ex(mdCtx, mdVal, &mdLen))
        {
            // printf("Message digest finalization failed.\n");
            EVP_MD_CTX_free(mdCtx);
            return -1;
        }

        EVP_MD_CTX_free(mdCtx);
        memcpy(output, mdVal, SHA_256_BYTES);
        return 0;
    }

    int hash_verify(packet decrypted_message, unsigned char *hash, encryption_data enc_data) {

        int ret_val = 0;

        // Creating buffer.
        unsigned char buffer[SHA_256_BYTES];
        memset(buffer, 0, SHA_256_BYTES);

        ret_val = getShaSum(decrypted_message, buffer);
        if (ret_val == -1) return ret_val;

        unsigned char decrypted_hash[SHA_256_BYTES];
        memset(decrypted_hash, 0, SHA_256_BYTES);
        decrypt(hash, SHA_256_BYTES, enc_data.key, enc_data.iv, decrypted_hash);

        return strncmp((const char *) buffer, (const char *) decrypted_hash, SHA_256_BYTES) == 0 ? 0 : -1;
    }

    int create_encrypted_packet(char *message, size_t length, encryption_data enc_data, packet *enc_pkt) {

        int ret_val = 0;

        packet pkt;
        memcpy(pkt.message, message, length);
        pkt.length = length;

        ret_val = encryption::encrypt(pkt, enc_data, enc_pkt);
        if (ret_val) return ret_val;

        size_t new_length = enc_pkt->length + IV_LEN;

        if (new_length > UDP_THEORETICAL_LIMIT) {
            ret_val = UDP_PACKET_TOO_LARGE;
            return ret_val;
        }

        for (int i = 0; i < IV_LEN; ++i) enc_pkt->message[enc_pkt->length + i] = enc_data.iv[i];
        enc_pkt->length = new_length;

        return ret_val;
    }
}