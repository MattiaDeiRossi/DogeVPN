#include "vpn_data_utils.h"

namespace vpn_data_utils {

	
	int init_vpn_client_packet_data(const packet *from, vpn_client_packet_data *ret_data) {


        int current_cursor = from->length - 1;
        memset(ret_data, 0, sizeof(vpn_client_packet_data));

        int j = 0;
        while (current_cursor >= 0) {

            char bdata = from->message[current_cursor--];

            /* Id has a specific length.
            *  When dealing with longer id, an error is returned.
            */
            if (j == ID_LEN && bdata != MESSAGE_SEPARATOR) {
                return -1;
            }
            
            if (bdata == MESSAGE_SEPARATOR) {

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
            IV_LEN,
            from->length,
            &current_cursor,
            true
        ) == -1) return -1;

        // Hash extraction.
        if (utils::read_reverse(
            ret_data->hash,
            from->message,
            SHA_256_BYTES,
            from->length,
            &current_cursor,
            true
        ) == -1) return -1;

        // Message extraction.
        size_t packet_length = utils::read_reverse(
            ret_data->encrypted_packet.message,
            from->message,
            MAX_MESSAGE_BYTES,
            from->length,
            &current_cursor,
            false
        );

        if (packet_length == -1) return -1;
        ret_data->encrypted_packet.length = packet_length;

        return 0;
    }

    void log_vpn_client_packet_data(vpn_client_packet_data *ret_data) {

        utils::println_sep(0);
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
        packet *from = &(ret_data->encrypted_packet);
        printf("Reading encrypted packet from client of size %ld bytes\n", from->length);
        utils::print_bytes("Printing packet bytes", (const char *) from->message, from->length, 8);
        utils::println_sep(0);
    }
}