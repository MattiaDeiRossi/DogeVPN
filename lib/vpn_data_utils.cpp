#include "vpn_data_utils.h"

namespace vpn_data_utils {

    void print_start_pad(size_t num) {
        for (size_t i = 0; i < num; i++) printf(" ");
    }

    void log_key_exchange_from_server_message(const key_exchange_from_server_message *message) {

        size_t key_size = encryption::MAX_KEY_SIZE;

        printf("Key exchange from server:\n");
        print_start_pad(4);
        printf("KEY: ");

        for (size_t i = 0; i < key_size; ++i) {
            if (i % 8 == 7 || i == key_size - 1) {
                printf("%02X\n", (unsigned char) message->key[i]);
                if (i != key_size - 1) {
                    print_start_pad(9);
                }
            } else {
                printf("%02X::", (unsigned char) message->key[i]);
            }
        }

        print_start_pad(4);
        printf("ID: ");

        for (size_t i = 0; i < SIZE_16; ++i) {
            if (message->id[i]) {
                printf("%c", message->id[i]);
            }
        }
        printf("\n");

        print_start_pad(4);
        printf("TUN IP: ");

        for (size_t i = 0; i < SIZE_64; ++i) {
            if (message->tun_ip[i]) {
                printf("%c", message->tun_ip[i]);
            }
        }
        printf("\n");
        
    }

    int parse_key_exchange_from_server_message(
        char *raw_message,
        size_t raw_message_size,
        key_exchange_from_server_message *message
    ) {

        unsigned char selector = 0;

        size_t user_id_size = 0;
        size_t tun_ip_size = 0;

        bzero(message, sizeof(key_exchange_from_server_message));

        for (size_t i = 0; i < raw_message_size; i++) {

            char byte_data = raw_message[i];
            int is_digit = isdigit(byte_data);
            int is_point = byte_data == MESSAGE_SEPARATOR_POINT;
            int is_div = byte_data == MESSAGE_SEPARATOR_DIV;

            /* Key extraction. */
            if (selector == 0) {
                message->key[i] = byte_data;
                selector = (i == encryption::MAX_KEY_SIZE - 1) ? 1 : selector;
                continue;
            }

            /* Id extraction. */
            if (selector == 1) {

                if (user_id_size == SIZE_16) {
                    fprintf(stderr, "parse_key_exchange_from_server_message: id of wrong size\n");
                    break;
                } else if (is_digit) {
                    message->id[user_id_size++] = byte_data;
                } else if (is_point) {
                    selector = 2;
                    continue;
                } else {
                    fprintf(stderr, "parse_key_exchange_from_server_message: malformed id\n");
                    break;
                }
            }

            /* Tun ip extraction. */
            if (selector == 2) {

                if (tun_ip_size == SIZE_64) {
                    fprintf(stderr, "parse_key_exchange_from_server_message: tun ip of wrong size\n");
                    break;
                } else if (is_digit || is_point || is_div) {
                    message->tun_ip[tun_ip_size++] = byte_data;
                } else {
                    break;
                }
            }
        }

        return (user_id_size > 0 && tun_ip_size > 0) ? 0 : -1;
    }

	
	int parse_packet(const encryption::packet *from, vpn_client_packet_data *ret_data) {

        ssize_t current_cursor = from->length - 1;
        memset(ret_data, 0, sizeof(vpn_client_packet_data));

        int j = 0;
        while (current_cursor >= 0) {

            char bdata = from->message[current_cursor--];

            /* Id cannot excedd a specific length.
            *  When dealing with longer id, an error is returned.
            */
            if (j == SIZE_16 && bdata != MESSAGE_SEPARATOR_POINT) {
                return -1;
            }
            
            if (bdata == MESSAGE_SEPARATOR_POINT) {

                /* The user id is the last part of the message after the IV vector.
                *  After encountering it the user id processing must stop.  
                */
                break;
            } if (!isdigit(bdata)) {

                /* An user id contains only digits.
                *  When a different character is encountered an error value is returned.
                */
                return -1;
            } else {

                ret_data->user_id[j++] = bdata;
            }

        }

        /* Sanity check.
        *  Id must not be empty.
        */
        if (j == 0) {
            return -1;
        }

        /* Id has been read in reverse.
        *  In order to extract it correctly, a reverse operation is applied. 
        */
        utils::reverse_string((char *) ret_data->user_id, j);

        // IV extraction.
        if (utils::read_reverse(
            ret_data->iv,
            from->message,
            encryption::MAX_IV_SIZE,
            from->length,
            &current_cursor,
            true
        ) == -1) return -1;

        // Hash extraction.
        if (utils::read_reverse(
            ret_data->hash,
            from->message,
            encryption::SHA_256_SIZE,
            from->length,
            &current_cursor,
            true
        ) == -1) return -1;

        // Message extraction.
        int packet_length = utils::read_reverse(
            ret_data->encrypted_packet.message,
            from->message,
            encryption::MAX_UDP_MESSAGE_SIZE,
            from->length,
            &current_cursor,
            false
        );

        if (packet_length == -1) return -1;
        ret_data->encrypted_packet.length = packet_length;

        return 0;
    }

    int build_packet_to_send(encryption::packet message, const char *key, int user_id, encryption::packet *result) {

        if (result == NULL) {
            utils::print_error("init_data_to_send: result cannot be NULL\n");
            return -1;
        }

        encryption::encryption_data e_data;
        memcpy(e_data.key, key, encryption::MAX_KEY_SIZE);
        if (ssl_utils::generate_rand_16(e_data.iv) == -1) return -1;
        if (encryption::encrypt(message, e_data, result) == -1) return -1;

        /* Composing the message:
        *   - hashing the original message
        *   - appending it to the packet to send
        */
        unsigned char hash[encryption::SHA_256_SIZE];
        if (encryption::getShaSum(message, hash) == -1) return -1;
        if (encryption::append(result, hash, encryption::SHA_256_SIZE) == -1) return -1;

        /* Composing the message:
        *   - appending the IV to the packet to send
        */
        if (encryption::append(result, e_data.iv, encryption::MAX_IV_SIZE) == -1) return -1;

        if (user_id != -1) {

            /* Composing the message:
            *   - appending the separator
            *   - appending the user id
            */

            unsigned char user_id_str[16];
            utils::int_to_string(user_id, (char *) user_id_str, sizeof(user_id_str));
            if (encryption::append(result, MESSAGE_SEPARATOR_POINT) == -1) return -1;
            if (encryption::append(result, user_id_str, strlen((const char *) user_id_str)) == -1) return -1;
        }

        return 0;
    }

    void log_vpn_client_packet_data(vpn_client_packet_data *ret_data) {

        printf("Reading VPN data from client packet\n");

        // Id must be long no more than 8 bytes.
        utils::print_yellow("   user_id");
        printf(":");
        for (int i = 0; i < 8; ++i) {
            if (ret_data->user_id[i] == 0) break;
            printf(" %c", ret_data->user_id[i]);
        }
        printf("\n");

        // Id must be long 16 bytes.
        utils::print_yellow("   iv");
        printf(":");
        utils::print_bytes("", (const char *) ret_data->iv, 16, 0);

        // Hash must be long 16 bytes.
        utils::print_yellow("   hash");
        printf(":");
        utils::print_bytes("", (const char *) ret_data->hash, 32, 0);

        // Priting packet data.
        encryption::packet *from = &(ret_data->encrypted_packet);
        printf("Reading encrypted packet from client of size %ld bytes\n", from->length);
        utils::print_bytes("Printing packet bytes", (const char *) from->message, from->length, 4);
    }

    void log_vpn_client_packet_data(const encryption::packet *from) {
        vpn_client_packet_data data;
        parse_packet(from, &data);
        log_vpn_client_packet_data(&data);
    }
}