#include "encryption.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <cstring>
#include <random>
#include <iostream>
#include <stdexcept>

#include <random_utils.h>

namespace encryption
{

    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext)
    {
        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Initialise the encryption operation.
         */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        ciphertext_len = len;

        /* Finalize the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        ciphertext_len += len;
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
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Initialise the decryption operation. */
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        plaintext_len = len;

        /* Finalize the decryption. Further plaintext bytes may be written at
         * this stage.
         */
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        plaintext_len += len;
        return plaintext_len;
    }

    encryption_data::encryption_data(const unsigned char *key)
    {

        /* Assuming the key follows specifications given (KEY: 32 bytes). */
        for (size_t i = 0; i < KEY_SIZE_32; i++)
        {
            this->key[i] = key[i];
        }

        random_utils::random rnd;
        rnd.generate_16(iv, false);
    }

    encryption_data::encryption_data(const unsigned char *key, const unsigned char *iv)
    {

        /* Here we are assuming the key and the iv follows specifications given:
         *   KEY:    32 bytes
         *   IV:     16 bytes
         */
        for (size_t i = 0; i < KEY_SIZE_32; i++)
        {
            this->key[i] = key[i];
        }

        for (size_t i = 0; i < IV_SIZE_16; i++)
        {
            this->iv[i] = iv == NULL ? 0 : iv[i];
        }
    }

    packet::packet()
    {

        bzero(buffer, SIZE_8_192);
        max_capacity = SIZE_8_192;
        size = 0;
    }

    packet::packet(unsigned const char *data, size_t num)
    {

        bzero(buffer, SIZE_8_192);
        max_capacity = SIZE_8_192;
        size = num;

        if (num > SIZE_8_192)
        {
            throw std::invalid_argument("data is too large");
        }

        for (size_t i = 0; i < num; i++)
        {
            buffer[i] = data[i];
        }
    }

    std::optional<packet> packet::encrypt(encryption_data enc_data)
    {

        packet result;

        /* Checking the length for returning an error in case of an UDP packet too large.
         * Abusing plus one just for laziness and safeness, ignoring modules.
         */
        size_t ciphertext_max_size = ((size / AES_256_CBC_PADDING) + 1) * AES_256_CBC_PADDING;
        if (ciphertext_max_size > result.max_capacity)
            return std::nullopt;

        ssize_t ciphertext_size = encryption::encrypt(buffer, size, enc_data.key, enc_data.iv, result.buffer);
        if (ciphertext_size == -1)
            return std::nullopt;

        result.size = ciphertext_size;
        return result;
    }

    std::optional<packet> packet::decrypt(encryption_data enc_data)
    {

        packet result;

        ssize_t plaintext_size = encryption::decrypt(
            buffer, size,
            enc_data.key, enc_data.iv,
            result.buffer);

        if (plaintext_size == -1)
            return std::nullopt;

        result.size = plaintext_size;
        return result;
    }

    bool packet::getShaSum(unsigned char *output)
    {

        EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
        unsigned char mdVal[SHA_256_SIZE];
        unsigned int mdLen;

        if (!EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL))
        {
            EVP_MD_CTX_free(mdCtx);
            return false;
        }

        if (!EVP_DigestUpdate(mdCtx, buffer, size))
        {
            EVP_MD_CTX_free(mdCtx);
            return false;
        }

        if (!EVP_DigestFinal_ex(mdCtx, mdVal, &mdLen))
        {
            EVP_MD_CTX_free(mdCtx);
            return false;
        }

        EVP_MD_CTX_free(mdCtx);
        memcpy(output, mdVal, SHA_256_SIZE);

        return true;
    }

    bool packet::valid_hash(unsigned const char *hash)
    {

        /* Creating the buffer with the correct hash size */
        unsigned char computed_hash[SHA_256_SIZE];
        if (!getShaSum(computed_hash))
            return false;

        for (size_t i = 0; i < SHA_256_SIZE; i++)
        {
            if (computed_hash[i] != hash[i])
            {
                return false;
            }
        }

        return true;
    }

    bool packet::append(unsigned const char *data, size_t num)
    {

        size_t current_size = size;
        if (current_size + num > max_capacity)
            return false;

        for (size_t i = 0; i < num; ++i)
            buffer[current_size + i] = data[i];
        size = current_size + num;
        return true;
    }

    bool packet::append(unsigned char data)
    {

        size_t current_size = size;
        if (current_size + 1 > max_capacity)
            return false;

        buffer[current_size] = data;
        size = current_size + 1;
        return true;
    }

    std::string packet::to_s()
    {

        char buff[128];
        bzero(buff, sizeof(buff));
        snprintf(buff, sizeof(buff) - 1, "packet(size:%ld)", size);

        std::string result = buff;
        return result;
    }

    std::string compute_hash(std::string message)
    {

        encryption::packet packet((unsigned const char *)message.c_str(), message.size());
        unsigned char output[SHA_256_SIZE];

        if (!packet.getShaSum(output))
        {

            /**/
            throw std::invalid_argument("hash cannot be computed");
        }

        std::string hash;
        for (size_t i = 0; i < sizeof(output); i++)
        {
            hash.push_back(output[i]);
        }

        return hash;
    }

    std::string compute_scrypt_hash(char *password, size_t n)
    {
        uint64_t N = 16384;
        uint32_t r = 8;
        uint32_t pa = 16;

        EVP_KDF *kdf;
        EVP_KDF_CTX *kctx;
        unsigned char out[32];
        OSSL_PARAM params[6], *p = params;

        kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
        kctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password, n);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0);
        *p++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &N);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &pa);
        *p = OSSL_PARAM_construct_end();

        if (EVP_KDF_derive(kctx, out, sizeof(out), params) <= 0)
        {
            throw std::invalid_argument("hash cannot be computed");
        }

        EVP_KDF_CTX_free(kctx);

        std::string hash;
        for (size_t i = 0; i < sizeof(out); i++)
        {
            /**/
            hash.push_back(out[i]);
        }

        return hash;
    }
}