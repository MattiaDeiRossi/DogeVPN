#include "encryption.h"

namespace encryption
{

    void handleErrors(void)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    packet::packet() {
        
        bzero(buffer, SIZE_8_192);
        max_capacity = SIZE_8_192;
        size = 0;
    }

    packet::packet(unsigned char *data, size_t num) {

        bzero(buffer, SIZE_8_192);
        max_capacity = SIZE_8_192;
        size = 0;

        if (num > SIZE_8_192) {
            throw std::invalid_argument("Data is too large");
        }

        for (size_t i = 0; i < num; i++) {
            buffer[i] = data[i];
        }
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

        /* Checking the length for returning an error in case of an UDP packet too large.
        *  Abusing plus one just for lazyness and safetyness, ignoring modules.
        */
        size_t ciphertext_len = ((pkt.size / AES_256_CBC_PADDING) + 1) * AES_256_CBC_PADDING;
        if (ciphertext_len > SIZE_32_768) {
            return -1;
        }

        packet encrypted_pkt;
        encrypted_pkt.size = encrypt(
            pkt.buffer, pkt.size, 
            enc_data.key, enc_data.iv, 
            encrypted_pkt.buffer
        );

        *enc_pkt = encrypted_pkt;
        return 0;
    }

    packet decrypt(packet encrypted_pkt, encryption_data enc_data)
    {

        packet pkt;
        pkt.size = encryption::decrypt(
            encrypted_pkt.buffer, encrypted_pkt.size, 
            enc_data.key, enc_data.iv, 
            pkt.buffer
        );

        return pkt;
    }

    int getShaSum(packet pkt, unsigned char *output)
    {

        EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
        unsigned char mdVal[SHA_256_SIZE];
        unsigned int mdLen;

        if (!EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL))
        {
            // printf("Message digest initialization failed.\n");
            EVP_MD_CTX_free(mdCtx);
            return -1;
        }

        // Hashes cnt bytes of data at d into the digest context mdCtx
        if (!EVP_DigestUpdate(mdCtx, pkt.buffer, pkt.size))
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
        memcpy(output, mdVal, SHA_256_SIZE);
        return 0;
    }

    int hash_verify(packet decrypted_message, unsigned char *hash) {

        // Creating buffer.
        unsigned char computed_hash[SHA_256_SIZE];
        if (getShaSum(decrypted_message, computed_hash) == -1) return -1;
        return strncmp((const char *) computed_hash, (const char *) hash, SHA_256_SIZE) == 0 ? 0 : -1;
    }

    int append(packet *output, unsigned char *data, size_t num) {

        size_t current_size = output->size;
        if (current_size + num > SIZE_32_768) return -1;

        for (size_t i = 0; i < num; ++i) output->buffer[current_size + i] = data[i];
        output->size = current_size + num;
        return 0;
    }

    int append(packet *output, unsigned char data) {

        size_t current_size = output->size;
        if (current_size + 1 > SIZE_32_768) return -1;

        output->buffer[current_size] = data;
        output->size = current_size + 1;
        return 0;
    }
}