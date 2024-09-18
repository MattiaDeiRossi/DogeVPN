#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <optional>
#include <string>

namespace encryption
{

    const int SIZE_8_192 = 8192;
    const int KEY_SIZE_32 = 32;
    const int IV_SIZE_16 = 16;
    const int SHA_256_SIZE = 32;
    const int AES_256_CBC_PADDING = 16;

    struct encryption_data
    {

        unsigned char key[KEY_SIZE_32];
        unsigned char iv[IV_SIZE_16];

        /* Build the encryption_data given a key 32 bytes long.
         * The IV of 16 bytes will be automatically generated.
         */
        encryption_data(const unsigned char *key);

        /* Build the encryption_data given a key 32 bytes long and the IV 16 bytes long */
        encryption_data(const unsigned char *key, const unsigned char *iv);
    };

    struct packet
    {

        unsigned char buffer[SIZE_8_192];
        size_t size;
        size_t max_capacity;

        /* Build an empty packet with all the memory initialized to zero */
        packet();

        /* Build a packet initialized with the given parameter */
        packet(unsigned const char *data, size_t num);

        /* Encrypt this packet given a valid object of type encryption_data. Since
         * encryption may fail (for example when the given argument is wrong, that is the key or the IV are not correct),
         * an optional value is returned.
         */
        std::optional<packet> encrypt(encryption_data enc_data);

        /* Decrypt this packet given a valid object of type encryption_data. Since
         * decryption may fail (for example when the given argument is wrong, that is the key or the IV are not correct),
         * an optional value is returned.
         */
        std::optional<packet> decrypt(encryption_data enc_data);

        /* Build an hash of this packet buffer, flowed in the given output argument */
        bool getShaSum(unsigned char *output);

        /* Check whether, given an hash, this packet represents the same hash */
        bool valid_hash(unsigned const char *hash);

        /* Modify this packet with the given argument */
        bool append(unsigned const char *data, size_t num);

        /* Modify this packet with the given argument */
        bool append(unsigned char data);

        /* Build a simple representation of this packet */
        std::string to_s();
    };

    std::string compute_hash(std::string message);

    std::string compute_scrypt_hash(char *password, size_t n);
}

#endif