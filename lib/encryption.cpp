#include "encryption.h"

namespace encryption
{

    struct r_engine {
        std::default_random_engine source;

        r_engine() {
            std::random_device r;
            source.seed(r());
        }
    } engine;

    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext)
    {
        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Initialise the encryption operation. */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        ciphertext_len = len;

        /* Finalise the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
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
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Initialise the decryption operation. */
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        plaintext_len = len;

        /* Finalise the decryption. Further plaintext bytes may be written at
         * this stage.
         */
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        plaintext_len += len;
        return plaintext_len;
    }

    encryption_data::encryption_data(const unsigned char *key) {

        /* Assuming the key follows specifications given (KEY: 32 bytes). */
        for (size_t i = 0; i < KEY_SIZE_32; i++) this->key[i] = key[i];

        unsigned char _iv[IV_SIZE_16];
        bzero(_iv, IV_SIZE_16);

        int rand_value = RAND_bytes(_iv, IV_SIZE_16);
        if (rand_value != 1) {

            /* When RAND_bytes cannot produce secured random bytes, a fallback is made by using
            *  the random std library.
            */
            std::uniform_int_distribution<uint32_t> uint_dist(0, UCHAR_MAX);  
            for (int i = 0; i < 16; i++) {
                _iv[i] = uint_dist(encryption::engine.source);
            }

            std::cerr << "RAND_bytes reported failure" << "\n";
        }

        memcpy(iv, _iv, IV_SIZE_16);
    }

    encryption_data::encryption_data(const unsigned char *key, const unsigned char *iv) {

        /* Here we are assuming the key and the iv follows specifications given:
        *   KEY:    32 bytes
        *   IV:     16 bytes
        */
        for (size_t i = 0; i < KEY_SIZE_32; i++) this->key[i] = key[i];
        for (size_t i = 0; i < IV_SIZE_16; i++) this->iv[i] = iv[i];
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
            throw std::invalid_argument("data is too large");
        }

        for (size_t i = 0; i < num; i++) {
            buffer[i] = data[i];
        }
    }

    std::optional<packet> packet::encrypt(encryption_data enc_data) {

        packet result;

        /* Checking the length for returning an error in case of an UDP packet too large.
        *  Abusing plus one just for lazyness and safetyness, ignoring modules.
        */
        size_t ciphertext_max_size = ((size / AES_256_CBC_PADDING) + 1) * AES_256_CBC_PADDING;
        if (ciphertext_max_size > result.max_capacity) return std::nullopt;

        /* check error*/
        ssize_t ciphertext_size = encryption::encrypt(buffer, size, enc_data.key, enc_data.iv, result.buffer);
        if (ciphertext_size == -1) return std::nullopt;

        result.size = ciphertext_size;
        return result;
    }

    std::optional<packet> packet::decrypt(encryption_data enc_data) {

        packet result;
        ssize_t plaintext_size = encryption::decrypt(
            buffer, size, 
            enc_data.key, enc_data.iv, 
            result.buffer
        );

        if (plaintext_size == -1) {
            return std::nullopt;
        }

        result.size = plaintext_size;
        return result;
    }

    ip_addresses::ip_addresses(unsigned char *buffer) {

        bzero(source_ip, 64);
        bzero(destination_ip, 64);

        struct ip *iphdr = (struct ip *) buffer;
        inet_ntop(AF_INET, &(iphdr->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iphdr->ip_dst), destination_ip, INET_ADDRSTRLEN);
    }

    ip_addresses packet::get_ip_addresses() {

        ip_addresses ips(buffer);
        return ips;
    }

    bool packet::getShaSum(unsigned char *output) {

        EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
        unsigned char mdVal[SHA_256_SIZE];
        unsigned int mdLen;

        if (!EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL)) {
            EVP_MD_CTX_free(mdCtx);
            return false;
        }

        /* Hashes cnt bytes of data at d into the digest context mdCtx. */
        if (!EVP_DigestUpdate(mdCtx, buffer, size)) {
            EVP_MD_CTX_free(mdCtx);
            return false;
        }

        if (!EVP_DigestFinal_ex(mdCtx, mdVal, &mdLen)) {
            EVP_MD_CTX_free(mdCtx);
            return false;
        }

        EVP_MD_CTX_free(mdCtx);
        memcpy(output, mdVal, SHA_256_SIZE);
        return true;
    }

    bool packet::valid_hash(unsigned char *hash) {

        /* Creating the buffer with the correct hash size. */
        unsigned char computed_hash[SHA_256_SIZE];
        if (!getShaSum(computed_hash)) return false;
        return strncmp((const char *) computed_hash, (const char *) hash, SHA_256_SIZE) == 0 ? true : false;
    }

    bool packet::append(const unsigned char *data, size_t num) {

        size_t current_size = size;
        if (current_size + num > max_capacity) return false;

        for (size_t i = 0; i < num; ++i) buffer[current_size + i] = data[i];
        size = current_size + num;
        return true;
    }

    bool packet::append(unsigned char data) {

        size_t current_size = size;
        if (current_size + 1 > max_capacity) return false;

        buffer[current_size] = data;
        size = current_size + 1;
        return true;
    }
}