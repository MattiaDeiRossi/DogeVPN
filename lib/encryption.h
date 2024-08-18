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
         * @param key symmetric key with which packet will be encrypted and decrypted
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

        /* Build a packet initialized with the given parameter
         * @param data array of char representing a message
         * @param num size fo the array
         */
        packet(unsigned char *data, size_t num);

        /* Encrypt this packet given a valid object of type encryption_data. Since
         * encryption may fail (for example when the given argument is wrong, that is the key or the IV are not correct),
         * an optional value is returned.
         * @param enc_data structure for the key and the IV to be used during the encryption
         * @return the encrypted packet on success, empty data on failure
         */
        std::optional<packet> encrypt(encryption_data enc_data);

        /* Decrypt this packet given a valid object of type encryption_data. Since
         * decryption may fail (for example when the given argument is wrong, that is the key or the IV are not correct),
         * an optional value is returned.
         * @param enc_data structure for the key and the IV to be used during the decryption
         * @return the decrypted packet on success, empty data on failure
         */
        std::optional<packet> decrypt(encryption_data enc_data);

        /* Build an hash of this packet buffer, flowed in the given output argument
         * @param output buffer where the hash will be reversed on success
         * @return true on success,false otherwise
         */
        bool getShaSum(unsigned char *output);

        /* Check whether, given an hash, this packet represents the same hash
         * @param hash to verify
         * @return true if the hash is the same, false otherwise
         */
        bool valid_hash(unsigned char *hash);

        /* Modify this packet with the given argument */
        bool append(const unsigned char *data, size_t num);

        /* Modify this packet with the given argument */
        bool append(unsigned char data);

        /* Build a simle representation of this packet */
        std::string to_s();
    };
}

#endif