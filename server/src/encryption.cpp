#include "encryption.h"

namespace encryption{

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


}