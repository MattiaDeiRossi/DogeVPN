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

    struct key_exchange_message {

        unsigned char key[encryption::MAX_KEY_SIZE];
        unsigned char id[SIZE_16];
        unsigned char tun_ip[SIZE_64];

        key_exchange_message(char *raw_message, size_t raw_message_size);

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

    struct vpn_client_packet_data {
        unsigned char user_id[SIZE_16];
        unsigned char iv[encryption::MAX_IV_SIZE];
        unsigned char hash[encryption::SHA_256_SIZE];
        encryption::packet encrypted_packet;
    };

    /* This function deals with extracting the information. 
    *  DogeVPN requires the payload to respect the following format:
    *   1.  First part of the payload is the original encrypted packet.
    *       The length is variable.
    *   2.  After the payload there is the hash of the message signed with the exchanged key.
    *       The main reason to exchange the hashed messsage is:
    *           - Avoiding that the user id leak allow everyone to send non-sense packet.
    *   3.  After the hashed part we have the IV
    *   4.  Then we have the user id:
    *           - This is needed to decrypt the message with correct key
    */
    int parse_packet(const encryption::packet *from, vpn_client_packet_data *ret_data);

    int build_packet_to_send(encryption::packet from, const char *key, int user_id, encryption::packet *result);

    void log_vpn_client_packet_data(vpn_client_packet_data *ret_data);

    void log_vpn_client_packet_data(const encryption::packet *from);
}

#endif