#ifndef VPN_DATA_UTILS_H
#define VPN_DATA_UTILS_H

#include <ctype.h>
#include <stdexcept>
#include "utils.h"
#include "encryption.h"
#include "ssl_utils.h"

namespace vpn_data_utils {

    const unsigned char SIZE_16 = 16;
    const unsigned char SIZE_64 = 64;

    const unsigned char MESSAGE_SEPARATOR_POINT =   '.';
    const unsigned char MESSAGE_SEPARATOR_DIV =     '/';
    const unsigned char MESSAGE_SEPARATOR_OPEN =    '(';
    const unsigned char MESSAGE_SEPARATOR_CLOSE =   ')';

    const unsigned short KEY_EXCHANGE_FROM_SERVER_MESSAGE_SIZE =    128;
    const unsigned short CREDENTIALS_FROM_CLIENT_MESSAGE =          256;

    struct raw_key_exchange_data {

        unsigned char buffer[KEY_EXCHANGE_FROM_SERVER_MESSAGE_SIZE];
        size_t buffer_capacity;

        raw_key_exchange_data();
    };

    struct key_exchange_data {

        unsigned char key[encryption::KEY_SIZE_32];
        unsigned char id[SIZE_16];
        unsigned char tun_ip[SIZE_64];

        key_exchange_data(char *raw_message, size_t raw_message_size);

        void log_key_exchange_from_server_message();
    };

    struct raw_credentials {

        size_t actual_size;
        char raw_message[CREDENTIALS_FROM_CLIENT_MESSAGE];

        raw_credentials(const char* username, const char* password);
    };

    struct credentials {

        char username[CREDENTIALS_FROM_CLIENT_MESSAGE];
        char password[CREDENTIALS_FROM_CLIENT_MESSAGE];

        credentials(const char* data, size_t num);

        void log_credentials_from_client_message();
    };

    struct udp_packet_data {
        unsigned char user_id[SIZE_16];
        unsigned char iv[encryption::IV_SIZE_16];
        unsigned char hash[encryption::SHA_256_SIZE];
        encryption::packet encrypted_packet;

        udp_packet_data();

        /* This function deals with extracting the information. 
        *  DogeVPN requires the payload to respect the following format:
        *   1.  First part of the payload is the original encrypted packet.
        *       The length is variable.
        *   2.  After the payload there is the hash of the message signed with the exchanged key;
        *       the main reason to exchange the hashed messsage is to avoid 
        *       that the user id leak allow everyone to send non-sense packet
        *   3.  After the hashed part we have the IV
        *   4.  Then we have the user id: this is needed to decrypt the message with correct key
        */
        udp_packet_data(const encryption::packet *from);

        std::optional<encryption::packet> decrypt(const unsigned char *key);

        void log();
    };

    std::optional<udp_packet_data> udp_packet_data_or_empty(const encryption::packet *from);

    std::optional<encryption::packet> build_packet_to_send(encryption::packet from, const char *key, int user_id);

    void log_udp_packet_data(const encryption::packet *from);
}

#endif